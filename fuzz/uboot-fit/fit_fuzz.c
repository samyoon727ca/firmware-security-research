// SPDX-License-Identifier: GPL-2.0+
/*
 * FIT format-check and signature-check fuzz target for the U-Boot sandbox.
 *
 * fit_check_format() is the first thing U-Boot runs on a FIT it has loaded,
 * before any signature is checked, so every byte it reads is attacker-chosen.
 * This target hands it one fuzzer input per call; when the format check
 * passes, it runs fit_config_verify() on the default configuration against a
 * control devicetree holding a required = "conf" key (P2's setup), which
 * reaches the config lookup, hashed-nodes, region building and the RSA check.
 *
 * When that verifies, a semantic oracle checks that verified equals booted:
 * the kernel bootm would boot, looked up by bootm's own fit_image_load() call,
 * must hash to the kernel the dev key signed. If it does not, the target
 * prints "UBOOT_FIT_ORACLE: verified!=booted" and aborts, so libFuzzer keeps
 * the input as a crash (the CVE-2021-27097 / CVE-2021-27138 class, which no
 * sanitizer sees).
 *
 * It uses U-Boot's own fuzz mechanism (CONFIG_FUZZ, FUZZ_TEST) so it can be
 * sent upstream as is. fuzz/uboot-fit/build.sh copies it into test/fuzz/ of
 * the pinned tree at build time; it is not built from this directory.
 *
 * Run: UBOOT_SB_FUZZ_TEST=fuzz_fit_check_format ./u-boot [libFuzzer args]
 * from a directory holding the control devicetree, FIT_FUZZ_CONTROL_DTB, and
 * the signed kernel's digest, FIT_FUZZ_KERNEL_SHA256.
 */

#include <bootstage.h>
#include <hexdump.h>
#include <image.h>
#include <mapmem.h>
#include <os.h>
#include <asm/global_data.h>
#include <stdio.h>
#include <linux/libfdt.h>
#include <linux/string.h>
#include <linux/types.h>
#include <test/fuzz.h>
#include <u-boot/sha256.h>

DECLARE_GLOBAL_DATA_PTR;

/* Inputs above this size are skipped; a real FIT header plus tree fits. */
#define FIT_FUZZ_MAX_LEN	(64 * 1024)

/*
 * Control devicetree with the dev public key, read from the working
 * directory (fuzz/uboot-fit/replay/control-dev.dtb, which ci-replay.sh copies
 * there). The sandbox's own control DTB has no /signature node, against which
 * fit_config_verify() accepts any FIT, so the target refuses to run without it.
 */
#define FIT_FUZZ_CONTROL_DTB	"control-dev.dtb"

/*
 * SHA-256, in hex, of the kernel payload the dev key signed, read from the
 * working directory (fuzz/uboot-fit/replay/p2-signed.kernel.sha256, which
 * make_seed.sh writes with the seed and ci-replay.sh copies there). Only the
 * dev key in FIT_FUZZ_CONTROL_DTB can make a FIT verify, and it signed this
 * kernel only, so any other kernel bytes that bootm would boot are a bypass.
 */
#define FIT_FUZZ_KERNEL_SHA256	"p2-signed.kernel.sha256"

/*
 * The sandbox's malloc() is U-Boot's own heap, which AddressSanitizer cannot
 * see into, so the input goes into a static buffer instead. The bytes after
 * the input are poisoned for each call: a read past the end of the input is
 * reported even when it stays inside the buffer.
 */
static u8 fit_fuzz_buf[FIT_FUZZ_MAX_LEN] __aligned(8);

#ifdef CONFIG_ASAN
void __asan_poison_memory_region(void const volatile *addr, size_t size);
void __asan_unpoison_memory_region(void const volatile *addr, size_t size);
#else
static inline void __asan_poison_memory_region(void const volatile *addr,
					       size_t size) {}
static inline void __asan_unpoison_memory_region(void const volatile *addr,
						 size_t size) {}
#endif

/* Copy one input into the buffer; false if its size is out of range. */
static bool fit_fuzz_load(const uint8_t *data, size_t size)
{
	/*
	 * fdt_check_header() reads a whole header before it looks at the
	 * size, as every caller has at least that much memory behind the
	 * pointer. Shorter inputs would only report that harness artefact.
	 */
	if (size < sizeof(struct fdt_header) || size > sizeof(fit_fuzz_buf))
		return false;

	__asan_unpoison_memory_region(fit_fuzz_buf, sizeof(fit_fuzz_buf));
	memcpy(fit_fuzz_buf, data, size);
	__asan_poison_memory_region(fit_fuzz_buf + size,
				    sizeof(fit_fuzz_buf) - size);
	return true;
}

/* The control DTB, read once; aborts if it holds no key to check against. */
static const void *fit_fuzz_control_fdt(void)
{
	static void *blob;
	int size, keys;

	if (blob)
		return blob;
	if (os_read_file(FIT_FUZZ_CONTROL_DTB, &blob, &size) ||
	    fdt_check_full(blob, size)) {
		printf("fit_fuzz: no valid %s in the working directory\n",
		       FIT_FUZZ_CONTROL_DTB);
		os_abort();
	}
	keys = fdt_subnode_offset(blob, 0, FIT_SIG_NODENAME);
	if (keys < 0 || fdt_first_subnode(blob, keys) < 0) {
		printf("fit_fuzz: %s has no /%s key\n", FIT_FUZZ_CONTROL_DTB,
		       FIT_SIG_NODENAME);
		os_abort();
	}

	return blob;
}

/*
 * fit_config_verify() on the default configuration, with the dev control DTB
 * as gd->fdt_blob, the key blob U-Boot's boot path verifies against. The
 * sandbox's own blob is put back afterwards. Returns 0 if it verifies, else
 * the error.
 */
static int fit_fuzz_config_verify(const void *fit)
{
	const void *saved = gd->fdt_blob;
	int conf, ret;

	gd->fdt_blob = fit_fuzz_control_fdt();
	conf = fit_conf_get_node(fit, NULL);
	ret = conf < 0 ? conf : fit_config_verify(fit, conf);
	gd->fdt_blob = saved;

	return ret;
}

/* The signed kernel's digest, read once; aborts if the file is not one. */
static const u8 *fit_fuzz_signed_digest(void)
{
	static u8 digest[SHA256_SUM_LEN];
	static bool loaded;
	char *hex;
	int size;

	if (loaded)
		return digest;
	if (os_read_file(FIT_FUZZ_KERNEL_SHA256, (void **)&hex, &size) ||
	    size < 2 * SHA256_SUM_LEN || size > 2 * SHA256_SUM_LEN + 1 ||
	    (size > 2 * SHA256_SUM_LEN && hex[2 * SHA256_SUM_LEN] != '\n') ||
	    hex2bin(digest, hex, SHA256_SUM_LEN)) {
		printf("fit_fuzz: no valid %s in the working directory\n",
		       FIT_FUZZ_KERNEL_SHA256);
		os_abort();
	}
	os_free(hex);
	loaded = true;

	return digest;
}

/* Verified FITs whose kernel bootm would not load: refused, not a bypass. */
static unsigned long fit_fuzz_not_booted;

/*
 * The verified-equals-booted oracle. Call it only once fit_config_verify()
 * has accepted the default configuration of @fit. It looks the kernel up as
 * bootm does for "bootm <addr>" (boot_get_kernel() in boot/bootm.c): the same
 * fit_image_load() call on the same buffer, default configuration,
 * IH_ARCH_DEFAULT, IH_TYPE_KERNEL, FIT_LOAD_IGNORED, with images.verify on
 * (as bootm_start() leaves it unless the "verify" variable says no) and the
 * dev control DTB as the key blob, so fit_image_load() runs its own config
 * and image hash checks first. If the bytes it returns do not hash to @want,
 * bootm would boot unsigned bytes: the process aborts with the marker line,
 * and libFuzzer saves the input.
 *
 * If fit_image_load() fails, bootm refuses the FIT and boots nothing, so that
 * is not a bypass: it is counted, and the input passes. Returns 0 if the
 * kernel matched, else the fit_image_load() error.
 *
 * The sandbox gives a pointer outside its RAM a sandbox address by allocating
 * a map tag the first time it sees that pointer, and keeps it: once for the
 * buffer, and once per kernel data offset in it, never once per input.
 */
static int fit_fuzz_oracle(const void *fit, const u8 *want)
{
	/* A zeroed copy of bootm's global "images", as bootm_start() makes it. */
	struct bootm_headers hdrs = { .verify = 1 };
	const void *saved = gd->fdt_blob;
	u8 got[SHA256_SUM_LEN];
	ulong data, len;
	const void *buf;
	int ret;

	gd->fdt_blob = fit_fuzz_control_fdt();
	ret = fit_image_load(&hdrs, map_to_sysmem(fit), NULL, NULL,
			     IH_ARCH_DEFAULT, IH_TYPE_KERNEL,
			     BOOTSTAGE_ID_FIT_KERNEL_START, FIT_LOAD_IGNORED,
			     &data, &len);
	gd->fdt_blob = saved;
	if (ret < 0) {
		printf("fit_fuzz: oracle: verified, but bootm would not load the kernel (%d); not a bypass, %lu so far\n",
		       ret, ++fit_fuzz_not_booted);
		return ret;
	}

	buf = map_sysmem(data, len);
	sha256_csum_wd(buf, len, got, CHUNKSZ_SHA256);
	unmap_sysmem(buf);
	if (memcmp(got, want, sizeof(got))) {
		/* On a line of its own: the checks above can leave one open. */
		printf("\nUBOOT_FIT_ORACLE: verified!=booted\n");
		os_abort();
	}

	return 0;
}

static int fuzz_fit_check_format(const uint8_t *data, size_t size)
{
	/* Read at the first call (libFuzzer's empty input), not at a first hit. */
	const u8 *want = fit_fuzz_signed_digest();

	/* The real size, so FIT_FULL_CHECK bounds the tree by the input. */
	if (fit_fuzz_load(data, size) && !fit_check_format(fit_fuzz_buf, size) &&
	    !fit_fuzz_config_verify(fit_fuzz_buf))
		fit_fuzz_oracle(fit_fuzz_buf, want);

	return 0;
}
FUZZ_TEST(fuzz_fit_check_format, 0);

/*
 * Seed check for fuzz/uboot-fit/ci-replay.sh, not a fuzz target: the same
 * call, but the process aborts unless fit_check_format() accepts the input.
 * Replaying the committed seeds through it shows that they get past the
 * format check in this build, not only that they do not crash. The empty
 * input libFuzzer always runs first is the one input it lets through.
 */
static int fuzz_fit_check_format_accept(const uint8_t *data, size_t size)
{
	int ret;

	if (!size)
		return 0;
	if (!fit_fuzz_load(data, size)) {
		printf("fit_fuzz: %zu-byte input is outside the target's size range\n",
		       size);
		os_abort();
	}
	ret = fit_check_format(fit_fuzz_buf, size);
	if (ret) {
		printf("fit_fuzz: fit_check_format() rejected a %zu-byte input: %d\n",
		       size, ret);
		os_abort();
	}

	return 0;
}
FUZZ_TEST(fuzz_fit_check_format_accept, 0);

/* Report a failed seed check and stop the process. */
static void fit_fuzz_fail(const char *what, int ret)
{
	printf("fit_fuzz: signed seed check failed: %s (%d)\n", what, ret);
	os_abort();
}

/* fit_image_verify() (1 if OK) with the dev control DTB as gd->fdt_blob. */
static int fit_fuzz_image_verify(const void *fit, int noffset)
{
	const void *saved = gd->fdt_blob;
	int ret;

	gd->fdt_blob = fit_fuzz_control_fdt();
	ret = fit_image_verify(fit, noffset);
	gd->fdt_blob = saved;

	return ret;
}

/*
 * Seed check for the signed seeds (the *.fit files in replay/), not a fuzz
 * target: the process aborts unless the input
 *  1. passes fit_check_format() and fit_config_verify() against the dev key,
 *     and its kernel passes fit_image_verify() (its sha256 hash node). The
 *     fuzz target's oracle then runs on it, and bootm's lookup must load a
 *     kernel that matches the signed digest (the oracle ran and stayed quiet);
 *  2. with one byte of the kernel payload flipped, is rejected. The config
 *     signature leaves out the "data" property (it covers each image's hash
 *     value instead), so the flip still passes fit_config_verify() and is
 *     caught by fit_image_verify(), as in fit_image_load(). Both results
 *     are asserted, and so is that the oracle sees bootm refuse it: verified
 *     but not booted is counted, not reported;
 *  3. with one byte of the kernel's hash value flipped, fails
 *     fit_config_verify() itself.
 */
static int fuzz_fit_config_verify_check(const uint8_t *data, size_t size)
{
	const void *payload;
	const u8 *value;
	size_t off, len;
	int kernel, hash, ret, vlen;

	if (!size)
		return 0;
	if (!fit_fuzz_load(data, size))
		fit_fuzz_fail("input size out of range", (int)size);
	ret = fit_check_format(fit_fuzz_buf, size);
	if (ret)
		fit_fuzz_fail("fit_check_format() rejected the seed", ret);
	ret = fit_fuzz_config_verify(fit_fuzz_buf);
	if (ret)
		fit_fuzz_fail("fit_config_verify() rejected the seed", ret);
	kernel = fit_conf_get_prop_node(fit_fuzz_buf,
					fit_conf_get_node(fit_fuzz_buf, NULL),
					FIT_KERNEL_PROP, IH_PHASE_NONE);
	if (kernel < 0)
		fit_fuzz_fail("no kernel in the default configuration", kernel);
	if (!fit_fuzz_image_verify(fit_fuzz_buf, kernel))
		fit_fuzz_fail("fit_image_verify() rejected the kernel", 0);
	ret = fit_fuzz_oracle(fit_fuzz_buf, fit_fuzz_signed_digest());
	if (ret)
		fit_fuzz_fail("bootm's lookup did not load the seed's kernel", ret);

	/* 2. One byte in the middle of the kernel payload. */
	ret = fit_image_get_data(fit_fuzz_buf, kernel, &payload, &len);
	if (ret || !len || (const u8 *)payload < fit_fuzz_buf ||
	    (const u8 *)payload + len > fit_fuzz_buf + size)
		fit_fuzz_fail("kernel payload is not inside the FIT", ret);
	off = (const u8 *)payload - fit_fuzz_buf + len / 2;
	fit_fuzz_buf[off] ^= 0x01;
	ret = fit_fuzz_config_verify(fit_fuzz_buf);
	if (ret)
		fit_fuzz_fail("fit_config_verify() now covers the payload; update this check",
			      ret);
	if (fit_fuzz_image_verify(fit_fuzz_buf, kernel))
		fit_fuzz_fail("fit_image_verify() accepted a flipped kernel byte", 1);
	ret = fit_fuzz_oracle(fit_fuzz_buf, fit_fuzz_signed_digest());
	if (ret >= 0)
		fit_fuzz_fail("bootm's lookup loaded a flipped kernel byte", ret);
	fit_fuzz_buf[off] ^= 0x01;

	/* 3. One byte of the kernel's signed hash value. */
	hash = fdt_subnode_offset(fit_fuzz_buf, kernel, FIT_HASH_NODENAME);
	value = hash < 0 ? NULL : fdt_getprop(fit_fuzz_buf, hash,
					      FIT_VALUE_PROP, &vlen);
	if (!value || vlen <= 0)
		fit_fuzz_fail("kernel has no hash value", hash);
	off = value - fit_fuzz_buf;
	fit_fuzz_buf[off] ^= 0x01;
	if (!fit_fuzz_config_verify(fit_fuzz_buf))
		fit_fuzz_fail("fit_config_verify() accepted a flipped hash value", 0);
	printf("fit_fuzz: %zu-byte signed seed verifies; kernel tampering rejected\n",
	       size);
	printf("fit_fuzz: oracle: bootm loads the signed kernel; quiet on the seed\n");

	return 0;
}
FUZZ_TEST(fuzz_fit_config_verify_check, 0);

/*
 * Oracle test hook for ci-replay.sh, not a fuzz target: the fuzz target's
 * path on a signed seed (format check, fit_config_verify(), then the oracle),
 * but with one bit of the expected digest flipped. bootm's lookup loads the
 * signed kernel as usual, which no longer matches, so the oracle must fire
 * (marker line, abort) on 2026.07 with no bypass input. Reaching this test is
 * the explicit test flag: the swapped digest exists only here, the fuzz
 * target always passes the one read from FIT_FUZZ_KERNEL_SHA256, and this
 * test runs only when named, UBOOT_SB_FUZZ_TEST=fuzz_fit_oracle_hook_check.
 */
static int fuzz_fit_oracle_hook_check(const uint8_t *data, size_t size)
{
	u8 want[SHA256_SUM_LEN];
	int ret;

	if (!size)
		return 0;
	if (!fit_fuzz_load(data, size))
		fit_fuzz_fail("input size out of range", (int)size);
	ret = fit_check_format(fit_fuzz_buf, size);
	if (ret)
		fit_fuzz_fail("fit_check_format() rejected the seed", ret);
	ret = fit_fuzz_config_verify(fit_fuzz_buf);
	if (ret)
		fit_fuzz_fail("fit_config_verify() rejected the seed", ret);
	memcpy(want, fit_fuzz_signed_digest(), sizeof(want));
	want[0] ^= 0x01;
	printf("\nfit_fuzz: oracle test hook: expected digest swapped, so the oracle must fire; a hit here is not a finding\n");
	ret = fit_fuzz_oracle(fit_fuzz_buf, want);
	fit_fuzz_fail("oracle test hook: the oracle did not fire", ret);

	return 0;
}
FUZZ_TEST(fuzz_fit_oracle_hook_check, 0);

/*
 * Verdict for confirm.sh, not a fuzz target: the fuzz target's path on one
 * input plus a line saying how far it got. confirm.sh runs it only on the
 * real-crypto build, so "verified" means fit_config_verify() with real RSA.
 */
static int fuzz_fit_confirm(const uint8_t *data, size_t size)
{
	const u8 *want = fit_fuzz_signed_digest();
	const char *step = "fit_check_format()";
	int ret;

	if (!fit_fuzz_load(data, size)) {
		printf("\nfit_fuzz: confirm: rejected by the size check (%zu bytes)\n", size);
		return 0;
	}
	ret = fit_check_format(fit_fuzz_buf, size);
	if (!ret) {
		step = "fit_config_verify()";
		ret = fit_fuzz_config_verify(fit_fuzz_buf);
	}
	if (ret) {
		printf("\nfit_fuzz: confirm: rejected by %s (%d)\n", step, ret);
		return 0;
	}
	ret = fit_fuzz_oracle(fit_fuzz_buf, want);
	printf("\nfit_fuzz: confirm: verified by fit_config_verify(); bootm %s\n",
	       ret ? "would not load the kernel" : "loads the signed kernel");

	return 0;
}
FUZZ_TEST(fuzz_fit_confirm, 0);
