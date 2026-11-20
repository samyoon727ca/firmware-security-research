// Trace every caller of a sanitizer function out to system()/popen() sinks and
// classify how each %s in the recovered shell-command format string is quoted.
//
// Why: an incomplete-blocklist sanitizer (e.g. FUN_0000ad8c @ 0xad8c in
// mainfunction.cgi, see ../finding-openvpn-cmdinjection.md) only makes a shell
// call safe when the filtered %s lands inside quotes. Patch diffing finds only
// the sites a vendor already fixed; this script searches outward from the
// sanitizer instead. Java GhidraScript (compiled with Ghidra's bundled JDK).
//
// What it does:
//   (1) callers = every function holding a reference to the sanitizer entry
//       point (or to a thunk of it);
//   (2) from each caller, follow callees down to <depth> levels (caller = level
//       0) and collect call sites of system / popen (matched by name, through
//       thunks and imports) and of variadic wrappers. A wrapper is any function
//       that calls system/popen on a buffer which the nearest preceding
//       sprintf/snprintf/vsprintf/vsnprintf in the same function built from one
//       of the wrapper's own parameters (its format argument), e.g. a
//       doSystem(fmt, ...)-style helper. The wrapper's internal sink call is
//       represented by each call of the wrapper and is not reported on its own;
//   (3) recover the command format string at each site:
//         (a) a constant string passed directly to system/popen;
//         (b) the constant format of the sprintf-family call in the same
//             function that writes the buffer later passed to the sink (nearest
//             preceding write, by address, to the same buffer);
//         (c) the constant format argument of a wrapper call.
//       A site whose format cannot be recovered is still emitted, with
//       format=null and a note saying why;
//   (4) classify each %s conversion (incl. %.*s, %-10s, %ls, %1$s) as single,
//       double or unquoted with classifyPercentS() (shell quoting rules);
//   (5) map each site to every CGI action whose handler reaches the site's
//       function within <depth>+1 call levels. The action table is read as in
//       dump_action_table.java: table base = pointer word at ACTION_TABLE_PTR,
//       then ACTION_RECORD_COUNT records of {name_ptr, handler, prolog}.
//       login_level is always null: the level is decided at runtime inside the
//       prolog and is not derived here, so the prolog address is reported instead.
//
// postScript args:  <output_file> [sanitizer_hex=0xad8c] [depth=2] [format=json|csv]
//   output_file    REQUIRED, no default. If it is missing or empty the script
//                  prints usage and writes nothing. Results are pre-disclosure
//                  material: the script warns (but still writes) when the path
//                  is not under a drafts/private/ directory.
//   sanitizer_hex  sanitizer entry address (an empty arg keeps the default).
//   depth          callee levels to follow from each caller (>= 0).
//   format         json (array of objects) or csv (one row per site, list
//                  fields joined by ';', an action written as
//                  name|handler|prolog|login_level).
//
// Output: one record per sink call site, fields:
//   sanitizer        sanitizer entry address
//   caller_fn        sanitizer caller reaching the site in the fewest levels
//                    (name@entry); any other callers reaching it go in note
//   sink_fn          function containing the sink call (name@entry)
//   sink_addr        address of the call instruction
//   sink             "system", "popen", or the wrapper function's name
//   format           recovered command format string, or null
//   percent_s_count  number of %s conversions in format (null if format is null)
//   quoting          list of single|double|unquoted, one per %s, in order
//   any_unquoted     true if any %s is unquoted (null if format is null)
//   actions          list of {name, handler, prolog, login_level}
//   note             recovery notes / additional callers, or null
//
// Console output is a single summary line (site count + output path); no
// format strings or site details are printed.
//@category firmware-diff
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;

public class trace_sanitizer_sinks extends GhidraScript {

    // ---- defaults / tunables -------------------------------------------------
    static final long DEFAULT_SANITIZER = 0xad8cL;
    static final int DEFAULT_DEPTH = 2;
    static final String DEFAULT_FORMAT = "json";
    /** Pointer word holding the action-table base (see dump_action_table.java). */
    static final long ACTION_TABLE_PTR = 0xb628L;
    /** Number of {name_ptr, handler, prolog} records in the action table. */
    static final int ACTION_RECORD_COUNT = 137;
    static final int ACTION_RECORD_SIZE = 12;
    static final int DECOMPILE_TIMEOUT_S = 60;
    static final int MAX_STR = 1024;

    static final Set<String> SINKS = Set.of("system", "popen");
    /** sprintf-family base name -> {dst arg index, fmt arg index} (incl. _FORTIFY_SOURCE forms). */
    static final Map<String, int[]> FORMATTERS = Map.of(
        "sprintf",       new int[] {0, 1},
        "vsprintf",      new int[] {0, 1},
        "snprintf",      new int[] {0, 2},
        "vsnprintf",     new int[] {0, 2},
        "sprintf_chk",   new int[] {0, 3},
        "vsprintf_chk",  new int[] {0, 3},
        "snprintf_chk",  new int[] {0, 4},
        "vsnprintf_chk", new int[] {0, 4});

    static final String TAG = "[trace_sanitizer_sinks] ";
    static final String USAGE = TAG
        + "usage: postScript trace_sanitizer_sinks.java <output_file> "
        + "[sanitizer_hex=0xad8c] [depth=2] [format=json|csv]  (output_file is required)";

    // ---- state -----------------------------------------------------------------
    private FunctionManager fm;
    private DecompInterface deco;
    private final Map<Function, HighFunction> hfCache = new HashMap<>();
    private final Map<Function, Wrapper> wrappers = new HashMap<>();
    private final Map<Function, List<Site>> scanCache = new HashMap<>();

    static class Wrapper {
        final int fmtSlot;                                  // 0-based parameter slot
        final Set<Address> basis = new LinkedHashSet<>();   // internal sink calls
        Wrapper(int slot) { fmtSlot = slot; }
    }

    static class Action {
        String name; long handler; long prolog; Set<Function> reach;
    }

    static class Site {
        final Address addr; final Function fn; final String sink;
        String format; final List<String> notes = new ArrayList<>();
        Function caller; int level = Integer.MAX_VALUE;
        final Set<Function> otherCallers = new LinkedHashSet<>();
        final List<Action> actions = new ArrayList<>();
        Site(Address a, Function f, String s) { addr = a; fn = f; sink = s; }
    }

    // ---- quote classifier --------------------------------------------------------

    /**
     * Classify every %s conversion in a printf format string by the shell quoting
     * span it sits in. Returns one entry per %s, in order: "single" (inside '...'),
     * "double" (inside "...") or "unquoted".
     *
     * Rules (the format bytes are what the shell sees once printf substitutes them):
     *  - "%%" is a literal percent and never starts a conversion.
     *  - A conversion is % [n$] [flags -+ #0] [width | * | *n$] [.precision | .* | .*n$]
     *    [length hh h l ll L q j z t] conv. Only conv 's' (so %s, %.*s, %-10s, %ls,
     *    %1$s ...) is reported; other conversions are skipped. The ' (grouping) flag
     *    is deliberately NOT accepted, so a quote after % is always a quote. A % that
     *    does not start a valid conversion is treated as a literal character.
     *  - Outside quotes, a backslash escapes the next character, so \' and \" do not
     *    open a span. Inside "...", a backslash escapes only $ ` " \ (so \" does not
     *    close the span). Inside '...', a backslash is literal and ' always closes.
     *  - A backslash never consumes a following %: in \%s the conversion still counts
     *    (the shell escapes only the first substituted byte).
     *  - ' inside "..." and " inside '...' are literal.
     */
    static List<String> classifyPercentS(String fmt) {
        final int NONE = 0, SQ = 1, DQ = 2;
        List<String> out = new ArrayList<>();
        if (fmt == null) return out;
        int st = NONE;
        int n = fmt.length();
        int i = 0;
        while (i < n) {
            char c = fmt.charAt(i);
            if (c == '%') {
                if (i + 1 < n && fmt.charAt(i + 1) == '%') { i += 2; continue; }
                int end = conversionEnd(fmt, i);
                if (end < 0) { i++; continue; }
                if (fmt.charAt(end) == 's')
                    out.add(st == SQ ? "single" : st == DQ ? "double" : "unquoted");
                i = end + 1;
                continue;
            }
            if (c == '\\') {
                if (st == SQ || i + 1 >= n || fmt.charAt(i + 1) == '%') { i++; continue; }
                char d = fmt.charAt(i + 1);
                if (st == DQ && d != '"' && d != '\\' && d != '$' && d != '`') { i++; continue; }
                i += 2;
                continue;
            }
            if (c == '\'' && st != DQ) { st = (st == SQ) ? NONE : SQ; i++; continue; }
            if (c == '"' && st != SQ) { st = (st == DQ) ? NONE : DQ; i++; continue; }
            i++;
        }
        return out;
    }

    /** Index of the conversion character of the spec starting at fmt[pct]=='%', or -1. */
    static int conversionEnd(String fmt, int pct) {
        int n = fmt.length();
        int j = skipPositional(fmt, pct + 1);
        while (j < n && "-+ #0".indexOf(fmt.charAt(j)) >= 0) j++;
        if (j < n && fmt.charAt(j) == '*') j = skipPositional(fmt, j + 1);
        else while (j < n && Character.isDigit(fmt.charAt(j))) j++;
        if (j < n && fmt.charAt(j) == '.') {
            j++;
            if (j < n && fmt.charAt(j) == '*') j = skipPositional(fmt, j + 1);
            else while (j < n && Character.isDigit(fmt.charAt(j))) j++;
        }
        if (fmt.startsWith("hh", j) || fmt.startsWith("ll", j)) j += 2;
        else if (j < n && "hlLqjzt".indexOf(fmt.charAt(j)) >= 0) j++;
        if (j < n && "diouxXeEfFgGaAcspnm".indexOf(fmt.charAt(j)) >= 0) return j;
        return -1;
    }

    /** Skip an optional "n$" positional index at j; returns j unchanged if absent. */
    static int skipPositional(String fmt, int j) {
        int k = j;
        while (k < fmt.length() && Character.isDigit(fmt.charAt(k))) k++;
        return (k > j && k < fmt.length() && fmt.charAt(k) == '$') ? k + 1 : j;
    }

    // ---- program helpers ----------------------------------------------------------

    private static String hex(long v) { return String.format("0x%08x", v); }

    private static String fnRef(Function f) {
        return f == null ? null : f.getName() + "@" + hex(f.getEntryPoint().getOffset());
    }

    private static Function resolveThunk(Function f) {
        if (f != null && f.isThunk()) {
            Function t = f.getThunkedFunction(true);
            if (t != null) return t;
        }
        return f;
    }

    /** Library-style base name: thunks resolved, leading '_' and any '@version' dropped. */
    private static String baseName(Function f) {
        if (f == null) return "";
        String n = resolveThunk(f).getName();
        int at = n.indexOf('@');
        if (at > 0) n = n.substring(0, at);
        while (n.startsWith("_")) n = n.substring(1);
        return n;
    }

    private Function callee(PcodeOp op) {
        if (op.getOpcode() != PcodeOp.CALL) return null;
        Function f = fm.getFunctionAt(op.getInput(0).getAddress());
        if (f != null) return f;
        for (Reference r : getReferencesFrom(op.getSeqnum().getTarget())) {
            if (!r.getReferenceType().isCall()) continue;
            f = fm.getFunctionAt(r.getToAddress());
            if (f != null) return f;
        }
        return null;
    }

    private HighFunction decompile(Function f) {
        if (f == null || f.isExternal() || f.isThunk()) return null;
        if (hfCache.containsKey(f)) return hfCache.get(f);
        HighFunction hf = null;
        DecompileResults r = deco.decompileFunction(f, DECOMPILE_TIMEOUT_S, monitor);
        if (r != null && r.decompileCompleted()) hf = r.getHighFunction();
        hfCache.put(f, hf);
        return hf;
    }

    private long readPtr(Address a) throws MemoryAccessException {
        if (currentProgram.getDefaultPointerSize() == 8) return getLong(a);
        return ((long) getInt(a)) & 0xffffffffL;
    }

    /** NUL-terminated printable string at addr, or null if it does not look like one. */
    private String readCString(long addr) {
        try {
            Address a = toAddr(addr);
            Memory mem = currentProgram.getMemory();
            if (!mem.contains(a)) return null;
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < MAX_STR; i++) {
                int c = mem.getByte(a.add(i)) & 0xff;
                if (c == 0) return sb.length() > 0 ? sb.toString() : null;
                if ((c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r') sb.append((char) c);
                else return null;
            }
            return null;   // unterminated within MAX_STR
        } catch (Exception e) {
            return null;
        }
    }

    /** Look through COPY / CAST / INDIRECT. */
    private static Varnode strip(Varnode v) {
        for (int guard = 0; v != null && guard < 32; guard++) {
            PcodeOp d = v.getDef();
            if (d == null) break;
            int oc = d.getOpcode();
            if (oc == PcodeOp.COPY || oc == PcodeOp.CAST || oc == PcodeOp.INDIRECT) v = d.getInput(0);
            else break;
        }
        return v;
    }

    /** Constant address carried by v (constant, or PTRSUB/INT_ADD of constants), else null. */
    private static Long constAddr(Varnode v) {
        v = strip(v);
        if (v == null) return null;
        if (v.isConstant()) return v.getOffset();
        PcodeOp d = v.getDef();
        if (d != null && d.getNumInputs() == 2
                && (d.getOpcode() == PcodeOp.PTRSUB || d.getOpcode() == PcodeOp.INT_ADD)) {
            Varnode a = strip(d.getInput(0)), b = strip(d.getInput(1));
            if (a != null && b != null && a.isConstant() && b.isConstant())
                return a.getOffset() + b.getOffset();
        }
        return null;
    }

    /** Constant C string an argument points at, or null. */
    private String constString(Varnode v) {
        v = strip(v);
        if (v == null) return null;
        Long a = constAddr(v);
        if (a != null) return readCString(a);
        try {
            // pointer held in a global word read directly (e.g. an ARM literal-pool DAT_)
            if (v.isAddress() && !v.getAddress().isStackAddress()
                    && currentProgram.getMemory().contains(v.getAddress()))
                return readCString(readPtr(v.getAddress()));
            PcodeOp d = v.getDef();
            if (d != null && d.getOpcode() == PcodeOp.LOAD && d.getNumInputs() >= 2) {
                Long pa = constAddr(d.getInput(1));
                if (pa != null) return readCString(readPtr(toAddr(pa)));
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    /** Parameter slot (0-based) of the function's own parameter v derives from, or -1. */
    private static int paramSlot(HighFunction hf, Varnode v) {
        v = strip(v);
        if (v == null) return -1;
        HighVariable h = v.getHigh();
        if (h == null) return -1;
        if (h instanceof HighParam) return ((HighParam) h).getSlot();
        LocalSymbolMap lsm = hf.getLocalSymbolMap();
        for (int i = 0; i < lsm.getNumParams(); i++) {
            HighSymbol s = lsm.getParamSymbol(i);
            if (s != null && s.getHighVariable() == h) return s.getCategoryIndex();
        }
        return -1;
    }

    /**
     * Argument ordinal of a function-input varnode under the function's calling
     * convention (assuming pointer-sized arguments), or -1. Call sites number their
     * inputs this way, while the callee's decompiled slot can be skewed (e.g. the
     * x86-64 varargs XMM save area shows up as extra leading parameters).
     */
    private int argOrdinal(Function f, Varnode in) {
        if (in == null || !in.isInput()) return -1;
        try {
            PrototypeModel m = f.getCallingConvention();
            if (m == null) m = currentProgram.getCompilerSpec().getDefaultCallingConvention();
            if (m == null) return -1;
            DataType[] types = new DataType[9];
            types[0] = VoidDataType.dataType;
            for (int i = 1; i < types.length; i++) types[i] = new PointerDataType();
            VariableStorage[] st = m.getStorageLocations(currentProgram, types, false);
            for (int i = 1; i < st.length; i++) {
                Varnode first = st[i] == null ? null : st[i].getFirstVarnode();
                if (first != null && first.getAddress().equals(in.getAddress())) return i - 1;
            }
        } catch (Exception e) {
            return -1;
        }
        return -1;
    }

    /**
     * Identity of the buffer a pointer argument refers to: base (constant, function
     * input such as the stack pointer, or high variable) plus constant offset.
     * Two arguments with the same key in one function refer to the same buffer.
     */
    private static String bufKey(Varnode v) {
        long off = 0;
        for (int guard = 0; guard < 16; guard++) {
            v = strip(v);
            if (v == null) return null;
            if (v.isConstant()) return "c:" + Long.toHexString(v.getOffset() + off);
            PcodeOp d = v.getDef();
            if (d != null) {
                int oc = d.getOpcode();
                if ((oc == PcodeOp.PTRSUB || oc == PcodeOp.INT_ADD) && d.getNumInputs() == 2) {
                    Varnode k = strip(d.getInput(1));
                    if (k != null && k.isConstant()) { off += k.getOffset(); v = d.getInput(0); continue; }
                }
                if (oc == PcodeOp.PTRADD && d.getNumInputs() == 3) {
                    Varnode idx = strip(d.getInput(1)), sz = d.getInput(2);
                    if (idx != null && idx.isConstant() && sz.isConstant()) {
                        off += idx.getOffset() * sz.getOffset(); v = d.getInput(0); continue;
                    }
                }
            }
            String base;
            if (v.isInput()) base = "in:" + v.getAddress();
            else if (v.getHigh() != null) base = "h:" + System.identityHashCode(v.getHigh());
            else base = "v:" + System.identityHashCode(v);
            return base + "+" + Long.toHexString(off);
        }
        return null;
    }

    private List<PcodeOpAST> callOps(HighFunction hf) {
        List<PcodeOpAST> out = new ArrayList<>();
        Iterator<PcodeOpAST> it = hf.getPcodeOps();
        while (it.hasNext()) {
            PcodeOpAST op = it.next();
            if (op.getOpcode() == PcodeOp.CALL) out.add(op);
        }
        return out;
    }

    /** Nearest sprintf-family call before 'at' whose destination is buffer 'key'. */
    private PcodeOpAST nearestWrite(List<PcodeOpAST> fmts, String key, Address at) {
        if (key == null) return null;
        PcodeOpAST best = null;
        for (PcodeOpAST fo : fmts) {
            int[] ix = FORMATTERS.get(baseName(callee(fo)));
            if (fo.getNumInputs() <= 1 + ix[0]) continue;
            if (!key.equals(bufKey(fo.getInput(1 + ix[0])))) continue;
            Address fa = fo.getSeqnum().getTarget();
            if (fa.compareTo(at) >= 0) continue;
            if (best == null || fa.compareTo(best.getSeqnum().getTarget()) > 0) best = fo;
        }
        return best;
    }

    private List<PcodeOpAST> formatterOps(List<PcodeOpAST> calls) {
        List<PcodeOpAST> out = new ArrayList<>();
        for (PcodeOpAST op : calls)
            if (FORMATTERS.containsKey(baseName(callee(op)))) out.add(op);
        return out;
    }

    // ---- wrapper detection ----------------------------------------------------------

    private void findWrappers(Set<Function> sinkFns) {
        Set<Function> holders = new LinkedHashSet<>();
        for (Function s : sinkFns) {
            for (Reference r : getReferencesTo(s.getEntryPoint())) {
                Function h = fm.getFunctionContaining(r.getFromAddress());
                if (h != null && !h.isThunk() && !h.isExternal()) holders.add(h);
            }
        }
        for (Function h : holders) {
            HighFunction hf = decompile(h);
            if (hf == null) continue;
            List<PcodeOpAST> calls = callOps(hf);
            List<PcodeOpAST> fmts = formatterOps(calls);
            if (fmts.isEmpty()) continue;
            for (PcodeOpAST op : calls) {
                if (!SINKS.contains(baseName(callee(op))) || op.getNumInputs() < 2) continue;
                Address at = op.getSeqnum().getTarget();
                PcodeOpAST w = nearestWrite(fmts, bufKey(op.getInput(1)), at);
                if (w == null) continue;
                int[] ix = FORMATTERS.get(baseName(callee(w)));
                if (w.getNumInputs() <= 1 + ix[1]) continue;
                Varnode fv = strip(w.getInput(1 + ix[1]));
                if (paramSlot(hf, fv) < 0) continue;          // format is not one of h's parameters
                int ord = argOrdinal(h, fv);
                final int slot = ord >= 0 ? ord : paramSlot(hf, fv);
                Wrapper wr = wrappers.computeIfAbsent(h, k -> new Wrapper(slot));
                if (wr.fmtSlot == slot) wr.basis.add(at);
            }
        }
    }

    // ---- per-function sink scan -------------------------------------------------------

    private List<Site> scan(Function f) {
        List<Site> cached = scanCache.get(f);
        if (cached != null) return cached;
        List<Site> out = new ArrayList<>();
        scanCache.put(f, out);
        HighFunction hf = decompile(f);
        if (hf == null) {
            if (!f.isExternal() && !f.isThunk()) scanByRefs(f, out);
            return out;
        }
        List<PcodeOpAST> calls = callOps(hf);
        List<PcodeOpAST> fmts = formatterOps(calls);
        Wrapper self = wrappers.get(f);
        for (PcodeOpAST op : calls) {
            Function c = callee(op);
            if (c == null) continue;
            String bn = baseName(c);
            Address at = op.getSeqnum().getTarget();
            if (SINKS.contains(bn)) {
                if (self != null && self.basis.contains(at)) continue;   // reported at wrapper calls
                Site s = new Site(at, f, bn);
                out.add(s);
                if (op.getNumInputs() < 2) { s.notes.add("sink call has no decoded argument"); continue; }
                Varnode arg = op.getInput(1);
                String k = constString(arg);
                if (k != null) { s.format = k; continue; }
                String key = bufKey(arg);
                PcodeOpAST w = nearestWrite(fmts, key, at);
                if (w == null) {
                    s.notes.add(key == null
                        ? "command argument is not a constant string; buffer not resolvable"
                        : "command argument is not a constant string; no preceding sprintf-family "
                            + "write to the same buffer in this function");
                    continue;
                }
                String wn = baseName(callee(w));
                String wat = hex(w.getSeqnum().getTarget().getOffset());
                int[] ix = FORMATTERS.get(wn);
                if (w.getNumInputs() <= 1 + ix[1]) {
                    s.notes.add("buffer built by " + wn + " at " + wat + " with no decoded format argument");
                    continue;
                }
                k = constString(w.getInput(1 + ix[1]));
                if (k != null) { s.format = k; s.notes.add("format from " + wn + " at " + wat); }
                else s.notes.add("buffer built by " + wn + " at " + wat + "; its format is not a constant string");
            } else {
                Function cw = resolveThunk(c);
                Wrapper w = wrappers.get(cw);
                if (w == null) continue;
                Site s = new Site(at, f, cw.getName());
                out.add(s);
                int idx = 1 + w.fmtSlot;
                if (op.getNumInputs() <= idx) {
                    s.notes.add("wrapper call has no decoded format argument (param " + w.fmtSlot + ")");
                    continue;
                }
                String k = constString(op.getInput(idx));
                if (k != null) s.format = k;
                else s.notes.add("wrapper format argument (param " + w.fmtSlot + ") is not a constant string");
            }
        }
        return out;
    }

    /** Decompile failed: still list direct sink / wrapper calls from the reference table. */
    private void scanByRefs(Function f, List<Site> out) {
        AddressIterator it = currentProgram.getReferenceManager()
            .getReferenceSourceIterator(f.getBody(), true);
        while (it.hasNext()) {
            Address from = it.next();
            for (Reference r : getReferencesFrom(from)) {
                if (!r.getReferenceType().isCall()) continue;
                Function c = fm.getFunctionAt(r.getToAddress());
                if (c == null) continue;
                String bn = baseName(c);
                Function cw = resolveThunk(c);
                String sink = SINKS.contains(bn) ? bn : (wrappers.containsKey(cw) ? cw.getName() : null);
                if (sink == null) continue;
                Site s = new Site(from, f, sink);
                s.notes.add("decompile failed; format not recovered");
                out.add(s);
                break;
            }
        }
    }

    // ---- call-graph walk ----------------------------------------------------------------

    /** Breadth-first callee walk: function -> minimal call level, up to maxLevel. */
    private Map<Function, Integer> reach(Function start, int maxLevel) {
        Map<Function, Integer> lvl = new LinkedHashMap<>();
        Deque<Function> q = new ArrayDeque<>();
        lvl.put(start, 0);
        q.add(start);
        while (!q.isEmpty()) {
            Function f = q.poll();
            int l = lvl.get(f);
            if (l >= maxLevel) continue;
            for (Function c : f.getCalledFunctions(monitor)) {
                Function r = resolveThunk(c);
                if (r == null || r.isExternal() || lvl.containsKey(r)) continue;
                lvl.put(r, l + 1);
                q.add(r);
            }
        }
        return lvl;
    }

    private Function functionFor(long addr) {
        Function f = fm.getFunctionAt(toAddr(addr));
        if (f == null && (addr & 1L) != 0) f = fm.getFunctionAt(toAddr(addr & ~1L));   // Thumb bit
        if (f == null) f = fm.getFunctionContaining(toAddr(addr));
        return f;
    }

    private String cstr(long ptr) {
        try {
            Address a = toAddr(ptr);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 120; i++) {
                byte b = getByte(a.add(i));
                if (b == 0) break;
                if (b >= 0x20 && b < 0x7f) sb.append((char) b);
                else sb.append('.');
            }
            return sb.toString();
        } catch (Exception e) { return "<unreadable>"; }
    }

    private List<Action> readActions(int levels) {
        List<Action> acts = new ArrayList<>();
        try {
            long base = readPtr(toAddr(ACTION_TABLE_PTR));
            for (int i = 0; i < ACTION_RECORD_COUNT; i++) {
                long rec = base + (long) i * ACTION_RECORD_SIZE;
                Action a = new Action();
                a.name = cstr(readPtr(toAddr(rec)));
                a.handler = readPtr(toAddr(rec + 4));
                a.prolog = readPtr(toAddr(rec + 8));
                Function h = functionFor(a.handler);
                if (h == null) continue;
                a.reach = reach(resolveThunk(h), levels).keySet();
                acts.add(a);
            }
        } catch (Exception e) {
            println(TAG + "warning: action table unreadable via " + hex(ACTION_TABLE_PTR)
                + "; actions left empty");
        }
        return acts;
    }

    // ---- output ---------------------------------------------------------------------------

    private static String js(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20 || c > 0x7e) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    private static String csv(String s) {
        if (s == null) return "";
        if (s.isEmpty() || s.matches("(?s).*[,\"\\r\\n].*") || s.startsWith(" ") || s.endsWith(" "))
            return "\"" + s.replace("\"", "\"\"") + "\"";
        return s;
    }

    private static String noteOf(Site s) {
        List<String> n = new ArrayList<>(s.notes);
        if (!s.otherCallers.isEmpty()) {
            List<String> o = new ArrayList<>();
            for (Function f : s.otherCallers) o.add(fnRef(f));
            n.add("also reached from: " + String.join(", ", o));
        }
        return n.isEmpty() ? null : String.join("; ", n);
    }

    private static void writeJson(PrintWriter out, List<Site> sites, String san) {
        out.println("[");
        for (int i = 0; i < sites.size(); i++) {
            Site s = sites.get(i);
            List<String> q = classifyPercentS(s.format);
            StringBuilder sb = new StringBuilder("  {");
            sb.append("\"sanitizer\": ").append(js(san));
            sb.append(", \"caller_fn\": ").append(js(fnRef(s.caller)));
            sb.append(", \"sink_fn\": ").append(js(fnRef(s.fn)));
            sb.append(", \"sink_addr\": ").append(js(hex(s.addr.getOffset())));
            sb.append(", \"sink\": ").append(js(s.sink));
            sb.append(", \"format\": ").append(js(s.format));
            sb.append(", \"percent_s_count\": ").append(s.format == null ? "null" : String.valueOf(q.size()));
            sb.append(", \"quoting\": [");
            for (int j = 0; j < q.size(); j++) sb.append(j > 0 ? ", " : "").append(js(q.get(j)));
            sb.append("], \"any_unquoted\": ")
                .append(s.format == null ? "null" : String.valueOf(q.contains("unquoted")));
            sb.append(", \"actions\": [");
            for (int j = 0; j < s.actions.size(); j++) {
                Action a = s.actions.get(j);
                sb.append(j > 0 ? ", " : "").append("{\"name\": ").append(js(a.name))
                    .append(", \"handler\": ").append(js(hex(a.handler)))
                    .append(", \"prolog\": ").append(js(hex(a.prolog)))
                    .append(", \"login_level\": null}");
            }
            sb.append("], \"note\": ").append(js(noteOf(s))).append('}');
            if (i + 1 < sites.size()) sb.append(',');
            out.println(sb);
        }
        out.println("]");
    }

    private static void writeCsv(PrintWriter out, List<Site> sites, String san) {
        out.println("sanitizer,caller_fn,sink_fn,sink_addr,sink,format,percent_s_count,"
            + "quoting,any_unquoted,actions,note");
        for (Site s : sites) {
            List<String> q = classifyPercentS(s.format);
            List<String> acts = new ArrayList<>();
            for (Action a : s.actions)
                acts.add(a.name + "|" + hex(a.handler) + "|" + hex(a.prolog) + "|");
            String[] row = {
                san, fnRef(s.caller), fnRef(s.fn), hex(s.addr.getOffset()), s.sink, s.format,
                s.format == null ? null : String.valueOf(q.size()),
                String.join(";", q),
                s.format == null ? null : String.valueOf(q.contains("unquoted")),
                String.join(";", acts), noteOf(s) };
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < row.length; i++) sb.append(i > 0 ? "," : "").append(csv(row[i]));
            out.println(sb);
        }
    }

    // ---- main ------------------------------------------------------------------------------

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1 || a[0] == null || a[0].trim().isEmpty()) {
            println(USAGE);
            return;
        }
        long sanAddr = DEFAULT_SANITIZER;
        int depth = DEFAULT_DEPTH;
        String format = DEFAULT_FORMAT;
        try {
            if (a.length >= 2 && !a[1].trim().isEmpty()) sanAddr = Long.decode(a[1].trim());
            if (a.length >= 3 && !a[2].trim().isEmpty()) depth = Integer.parseInt(a[2].trim());
            if (a.length >= 4 && !a[3].trim().isEmpty()) format = a[3].trim().toLowerCase();
        } catch (NumberFormatException e) {
            println(USAGE);
            println(TAG + "error: bad sanitizer_hex or depth argument");
            return;
        }
        if (depth < 0 || !(format.equals("json") || format.equals("csv"))) {
            println(USAGE);
            println(TAG + "error: depth must be >= 0 and format json or csv");
            return;
        }

        File outFile = new File(a[0].trim()).getAbsoluteFile();
        String norm = outFile.toPath().normalize().toString().replace('\\', '/');
        if (!norm.contains("/drafts/private/"))
            println(TAG + "WARNING: output path is not under drafts/private/ - results are "
                + "pre-disclosure material; keep them out of tracked paths");

        fm = currentProgram.getFunctionManager();
        Function san = fm.getFunctionAt(toAddr(sanAddr));
        if (san == null) san = fm.getFunctionContaining(toAddr(sanAddr));
        if (san == null) {
            println(TAG + "error: no function at sanitizer address " + hex(sanAddr) + "; nothing written");
            return;
        }
        String sanStr = hex(san.getEntryPoint().getOffset());

        deco = new DecompInterface();
        deco.openProgram(currentProgram);
        try {
            // (1) sanitizer callers (references to its entry point or to any thunk of it)
            Set<Address> targets = new LinkedHashSet<>();
            targets.add(san.getEntryPoint());
            Address[] thunks = san.getFunctionThunkAddresses(true);
            if (thunks != null) for (Address t : thunks) targets.add(t);
            Set<Function> callerSet = new LinkedHashSet<>();
            for (Address t : targets) {
                for (Reference r : getReferencesTo(t)) {
                    Function c = fm.getFunctionContaining(r.getFromAddress());
                    if (c == null || c.equals(san) || c.isThunk()) continue;
                    callerSet.add(c);
                }
            }
            List<Function> callers = new ArrayList<>(callerSet);
            callers.sort((x, y) -> x.getEntryPoint().compareTo(y.getEntryPoint()));

            // sink functions (system/popen by name, incl. thunks and external imports) + wrappers
            Set<Function> sinkFns = new LinkedHashSet<>();
            FunctionIterator it = fm.getFunctions(true);
            while (it.hasNext()) { Function f = it.next(); if (SINKS.contains(baseName(f))) sinkFns.add(f); }
            it = fm.getExternalFunctions();
            while (it.hasNext()) { Function f = it.next(); if (SINKS.contains(baseName(f))) sinkFns.add(f); }
            findWrappers(sinkFns);

            // (2) walk callees from each caller and collect sites (closest caller wins)
            Map<Address, Site> sites = new LinkedHashMap<>();
            for (Function c : callers) {
                for (Map.Entry<Function, Integer> e : reach(c, depth).entrySet()) {
                    for (Site s : scan(e.getKey())) {
                        int lvl = e.getValue();
                        if (s.caller == null) { s.caller = c; s.level = lvl; }
                        else if (s.caller.equals(c)) continue;
                        else if (lvl < s.level) {
                            s.otherCallers.add(s.caller); s.caller = c; s.level = lvl;
                            s.otherCallers.remove(c);
                        } else s.otherCallers.add(c);
                        sites.put(s.addr, s);
                    }
                }
            }
            List<Site> list = new ArrayList<>(sites.values());
            list.sort((x, y) -> x.addr.compareTo(y.addr));

            // (5) action mapping: handler reaches the site's function within depth+1 levels
            if (!list.isEmpty()) {
                List<Action> acts = readActions(depth + 1);
                for (Site s : list)
                    for (Action act : acts)
                        if (act.reach.contains(s.fn)) s.actions.add(act);
            }

            File parent = outFile.getParentFile();
            if (parent != null) parent.mkdirs();
            try (PrintWriter out = new PrintWriter(new FileWriter(outFile))) {
                if (format.equals("csv")) writeCsv(out, list, sanStr);
                else writeJson(out, list, sanStr);
            }
            println(TAG + list.size() + " sink site(s) from " + callers.size()
                + " sanitizer caller(s) -> " + outFile.getPath());
        } finally {
            deco.dispose();
        }
    }
}
