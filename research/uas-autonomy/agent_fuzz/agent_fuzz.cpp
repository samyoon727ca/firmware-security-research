// agent_fuzz.cpp — Phase 2 / target B: in-process fuzz harness for the eProsima
// Micro-XRCE-DDS **Agent**'s XRCE message-parse entry.
//
// Where H1 fuzzed the *client-side* `ucdr` C decoders, target B fuzzes the **Agent-side**
// path: the C++ `InputMessage` class + the generated `dds::xrce::*` types, deserialized with
// **Fast-CDR** (XCDRv1). This is the first code that touches attacker bytes on the broker once
// a frame arrives on the transport (UDP:8888 / TCP / serial) — the network-reachable,
// unauthenticated TB-X1 surface, one layer up from `ucdr`.
//
// The harness mirrors Processor::process_submessage: construct InputMessage(bytes), then walk
// submessages, deserializing each payload type by submessage-id exactly as the Agent dispatch
// does (CREATE -> CREATE_Payload reaches the entity-representation union = H3; the default/raw
// path exercises get_raw_payload). We stop at PARSE — no ProxyClient, no DDS domain, no
// network, no vehicle. ASan/UBSan turn any OOB / UB inside Fast-CDR or the type deserializers
// into a recorded crash; Fast-CDR's own exceptions are caught by InputMessage (the Agent's
// defense) and are the *safe* outcome.
//
// DEFENSIVE research harness. Parses bytes in-process only. See ../phase2-h1-fuzz-harness-spec.md
// (target B row) and ../phase2-micro-xrce-dds-scope.md.
//
// Two build modes (see CMakeLists.txt):
//   * libFuzzer  : clang -fsanitize=fuzzer,address,undefined   -> LLVMFuzzerTestOneInput
//   * standalone : -DAGENT_FUZZ_STANDALONE                      -> main(): --selftest / replay
//
// Stage 2 (binary entity representation). At the InputMessage stage a
// REPRESENTATION_IN_BINARY body is only an opaque octet sequence; the Agent decodes it in a
// SECOND Fast-CDR pass inside <Entity>::create() (Participant.cpp, Topic.cpp, Publisher.cpp,
// Subscriber.cpp, DataWriter.cpp, DataReader.cpp, Requester.cpp, Replier.cpp), with the
// endianness taken from the CREATE submessage flags. decode_binary_rep() mirrors that pass, so
// the OBJK_*_Binary / *_QosBinary decoders are fuzzed too. Seeds that reach it are produced by
// `agent_fuzz_standalone --gen-seeds <dir>` using the Agent's own serialize().
#include <uxr/agent/message/InputMessage.hpp>
#include <uxr/agent/types/XRCETypes.hpp>

#include <fastcdr/Cdr.h>
#include <fastcdr/FastBuffer.h>
#include <fastcdr/exceptions/Exception.h>

#include <cstdint>
#include <cstddef>
#include <vector>

// InputMessage's only out-of-line member is log_error() (defined in InputMessage.cpp, which
// pulls in Logger/spdlog + the generated config.hpp). We stub it so the harness links against
// just Fast-CDR + the parse objects. Logging is irrelevant to memory safety.
namespace eprosima {
namespace uxr {
void InputMessage::log_error() {}
} // namespace uxr
} // namespace eprosima

using eprosima::uxr::InputMessage;

// Deserialize one XRCE payload of type T for the current submessage (drives its Fast-CDR path).
template <class T>
static bool pull(InputMessage& msg)
{
    T data;
    return msg.get_payload(data);
}

// Stage-2 counters: how many binary representations were handed to an OBJK_*_Binary decoder,
// and how many decoded cleanly. Read by the self-test as a positive control on reach.
static unsigned long g_bin_attempts = 0;
static unsigned long g_bin_decoded = 0;

// Mirror of the REPRESENTATION_IN_BINARY case in <Entity>::create(): copy the representation,
// wrap its octets in a fresh FastBuffer/Cdr (endianness from the submessage flags, XCDRv1) and
// deserialize the binary struct, catching only Fast-CDR exceptions exactly as the Agent does.
template <class Rep, class Bin>
static void decode_bin(const Rep& representation, Bin& bin)
{
    if (representation.representation()._d() != ::dds::xrce::REPRESENTATION_IN_BINARY)
    {
        return;
    }
    auto rep = representation.representation();
    eprosima::fastcdr::FastBuffer fastbuffer{
        reinterpret_cast<char*>(const_cast<uint8_t*>(rep.binary_representation().data())),
        rep.binary_representation().size()};
    eprosima::fastcdr::Cdr::Endianness endianness =
            static_cast<eprosima::fastcdr::Cdr::Endianness>(representation.endianness());
    eprosima::fastcdr::Cdr cdr(fastbuffer, endianness, eprosima::fastcdr::CdrVersion::XCDRv1);
    ++g_bin_attempts;
    try
    {
        bin.deserialize(cdr);
    }
    catch (eprosima::fastcdr::exception::Exception& /*exception*/)
    {
        return;
    }
    ++g_bin_decoded;
}

// Mirror of ProxyClient::create_object's dispatch by ObjectKind into <Entity>::create().
static void decode_binary_rep(const ::dds::xrce::ObjectVariant& v)
{
    namespace xr = ::dds::xrce;
    switch (v._d())
    {
        case xr::OBJK_PARTICIPANT:
        {
            xr::OBJK_DomainParticipant_Binary bin;
            bin.domain_id(v.participant().domain_id());
            decode_bin(v.participant(), bin);
            break;
        }
        case xr::OBJK_TOPIC:      { xr::OBJK_Topic_Binary bin;      decode_bin(v.topic(), bin);       break; }
        case xr::OBJK_PUBLISHER:  { xr::OBJK_Publisher_Binary bin;  decode_bin(v.publisher(), bin);   break; }
        case xr::OBJK_SUBSCRIBER: { xr::OBJK_Subscriber_Binary bin; decode_bin(v.subscriber(), bin);  break; }
        case xr::OBJK_DATAWRITER: { xr::OBJK_DataWriter_Binary bin; decode_bin(v.data_writer(), bin); break; }
        case xr::OBJK_DATAREADER: { xr::OBJK_DataReader_Binary bin; decode_bin(v.data_reader(), bin); break; }
        case xr::OBJK_REQUESTER:  { xr::OBJK_Requester_Binary bin;  decode_bin(v.requester(), bin);   break; }
        case xr::OBJK_REPLIER:    { xr::OBJK_Replier_Binary bin;    decode_bin(v.replier(), bin);     break; }
        default:
            break;
    }
}

// CREATE: parse the payload, then (as Processor::process_create_submessage does) stamp the
// submessage endianness onto the representation and run the stage-2 binary decode.
static bool pull_create(InputMessage& msg)
{
    ::dds::xrce::CREATE_Payload payload;
    if (!msg.get_payload(payload))
    {
        return false;
    }
    ::dds::xrce::Endianness endianness =
            static_cast< ::dds::xrce::Endianness>(msg.get_subheader().flags() & 0x01);
    payload.object_representation().endianness(endianness);
    decode_binary_rep(payload.object_representation());
    return true;
}

static void decode_once(const uint8_t* data, size_t size)
{
    if (size == 0 || size > 4096)
    {
        return;
    }

    // InputMessage copies the buffer internally; hand it a mutable, exactly-sized copy.
    std::vector<uint8_t> buf(data, data + size);
    InputMessage msg(buf.data(), buf.size());   // ctor: deserialize MessageHeader + count submessages
    if (!msg.is_valid_xrce_message())
    {
        return;
    }

    // Mirror Processor::process_submessage: walk submessages, decode each payload type by id.
    // Faithful traversal: stop when a submessage fails to parse (as the real while-loop does).
    int guard = 0;
    while (msg.prepare_next_submessage() && guard++ < 64)
    {
        bool ok;
        switch (msg.get_subheader().submessage_id())
        {
            case ::dds::xrce::CREATE_CLIENT: ok = pull< ::dds::xrce::CREATE_CLIENT_Payload>(msg); break;
            case ::dds::xrce::CREATE:        ok = pull_create(msg);                               break; // H3: entity rep + stage 2
            case ::dds::xrce::GET_INFO:      ok = pull< ::dds::xrce::GET_INFO_Payload>(msg);      break;
            case ::dds::xrce::DELETE_ID:     ok = pull< ::dds::xrce::DELETE_Payload>(msg);        break;
            case ::dds::xrce::WRITE_DATA:    ok = pull< ::dds::xrce::WRITE_DATA_Payload_Data>(msg); break;
            case ::dds::xrce::READ_DATA:     ok = pull< ::dds::xrce::READ_DATA_Payload>(msg);     break;
            case ::dds::xrce::ACKNACK:       ok = pull< ::dds::xrce::ACKNACK_Payload>(msg);       break;
            case ::dds::xrce::HEARTBEAT:     ok = pull< ::dds::xrce::HEARTBEAT_Payload>(msg);     break;
            case ::dds::xrce::TIMESTAMP:     ok = pull< ::dds::xrce::TIMESTAMP_Payload>(msg);     break;
            default:
            {
                // Unknown id (incl. FRAGMENT, which the Agent reassembles in Session — H2, a
                // deeper target). Exercise the raw-copy path against a bounded destination.
                uint8_t raw[1024];
                ok = msg.get_raw_payload(raw, sizeof(raw));
                break;
            }
        }
        if (!ok)
        {
            break;
        }
    }
}

#ifdef AGENT_FUZZ_STANDALONE
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

// ---------------------------------------------------------------------------------------
// Serialize-generated seeds for the binary entity-representation path. Each seed is a valid
// XRCE message carrying one CREATE submessage whose representation is REPRESENTATION_IN_BINARY,
// built with the Agent's own serialize() so the nesting (octet-sequence length, optional-member
// flags, alignment) is exactly what the stage-2 decoder expects. 8 entity kinds x {minimal,
// full optionals} x {little, big endian} = 32 seeds.
// ---------------------------------------------------------------------------------------
namespace seedgen {
namespace xr = ::dds::xrce;
using eprosima::fastcdr::Cdr;
using eprosima::fastcdr::FastBuffer;

struct Seed
{
    std::string name;
    std::vector<uint8_t> bytes;
};

template <class Bin>
static std::vector<uint8_t> ser_bin(const Bin& bin, bool little)
{
    std::vector<char> buf(2048, 0);
    FastBuffer fb(buf.data(), buf.size());
    Cdr cdr(fb, little ? Cdr::LITTLE_ENDIANNESS : Cdr::BIG_ENDIANNESS, eprosima::fastcdr::CdrVersion::XCDRv1);
    bin.serialize(cdr);
    return std::vector<uint8_t>(buf.begin(), buf.begin() + cdr.get_serialized_data_length());
}

// MessageHeader + SubmessageHeader(CREATE) + CREATE_Payload, laid out as OutputMessage does
// (one Cdr over the whole buffer, payload in the endianness named by the submessage flag).
static std::vector<uint8_t> make_create(const xr::ObjectVariant& variant, bool little)
{
    xr::CREATE_Payload payload;
    payload.request_id({{0x00, 0x01}});
    payload.object_id({{0x00, uint8_t(0x10 | variant._d())}});
    payload.object_representation(variant);

    std::vector<char> buf(4096, 0);
    FastBuffer fb(buf.data(), buf.size());
    Cdr cdr(fb, Cdr::DEFAULT_ENDIAN, eprosima::fastcdr::CdrVersion::XCDRv1);

    xr::MessageHeader header;
    header.session_id(0x81);
    header.stream_id(0x80);
    header.sequence_nr(0x0000);
    header.serialize(cdr);

    const size_t sub_off = cdr.get_serialized_data_length();
    xr::SubmessageHeader subheader;
    subheader.submessage_id(xr::CREATE);
    subheader.flags(little ? 0x01 : 0x00);
    subheader.submessage_length(0);
    subheader.serialize(cdr);

    cdr.change_endianness(little ? Cdr::LITTLE_ENDIANNESS : Cdr::BIG_ENDIANNESS);
    const size_t body_off = cdr.get_serialized_data_length();
    payload.serialize(cdr);
    const size_t end_off = cdr.get_serialized_data_length();

    const uint16_t body_len = uint16_t(end_off - body_off);   // submessage_length is always LE
    buf[sub_off + 2] = char(body_len & 0xFF);
    buf[sub_off + 3] = char(body_len >> 8);
    return std::vector<uint8_t>(buf.begin(), buf.begin() + end_off);
}

static xr::OBJK_Endpoint_QosBinary endpoint_qos()
{
    xr::OBJK_Endpoint_QosBinary q;
    q.qos_flags(xr::EndpointQosFlags(xr::is_reliable | xr::is_history_keep_last));
    q.history_depth(8);
    q.deadline_msec(1000);
    q.lifespan_msec(2000);
    q.user_data(std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF});
    return q;
}

static std::vector<Seed> build_all()
{
    std::vector<Seed> out;
    const xr::ObjectId parent{{0x00, 0x11}};
    for (int le = 1; le >= 0; --le)
    {
        const bool little = (le == 1);
        for (int full = 0; full <= 1; ++full)
        {
            const std::string tag = std::string(full ? "full" : "min") + (little ? "_le" : "_be");
            auto add = [&](const char* kind, const xr::ObjectVariant& v)
                    {
                        out.push_back({std::string("create_bin_") + kind + "_" + tag, make_create(v, little)});
                    };
            {
                xr::OBJK_DomainParticipant_Binary bin;
                if (full) { bin.domain_referente(std::string("domain_ref")); bin.qos_profile(std::string("participant_profile")); }
                xr::OBJK_PARTICIPANT_Representation rep;
                rep.domain_id(0);
                rep.representation().binary_representation(ser_bin(bin, little));
                xr::ObjectVariant v; v.participant(rep); add("participant", v);
            }
            {
                xr::OBJK_Topic_Binary bin;
                bin.topic_name(std::string("rt/fuzz_topic"));
                if (full) { bin.type_name(std::string("std_msgs::msg::dds_::String_")); bin.type_identifier(std::string("type_id")); }
                xr::OBJK_TOPIC_Representation rep;
                rep.participant_id(parent);
                rep.representation().binary_representation(ser_bin(bin, little));
                xr::ObjectVariant v; v.topic(rep); add("topic", v);
            }
            {
                xr::OBJK_Publisher_Binary bin;
                if (full)
                {
                    xr::OBJK_PUBLISHER_QosBinary q;
                    q.partitions(std::vector<std::string>{"part_a", "part_b"});
                    q.group_data(std::vector<std::string>{"group"});
                    bin.publisher_name(std::string("publisher"));
                    bin.qos(q);
                }
                xr::OBJK_PUBLISHER_Representation rep;
                rep.participant_id(parent);
                rep.representation().binary_representation(ser_bin(bin, little));
                xr::ObjectVariant v; v.publisher(rep); add("publisher", v);
            }
            {
                xr::OBJK_Subscriber_Binary bin;
                if (full)
                {
                    xr::OBJK_SUBSCRIBER_QosBinary q;
                    q.partitions(std::vector<std::string>{"part_a", "part_b"});
                    q.group_data(std::vector<uint8_t>{0x01, 0x02, 0x03});
                    bin.subscriber_name(std::string("subscriber"));
                    bin.qos(q);
                }
                xr::OBJK_SUBSCRIBER_Representation rep;
                rep.participant_id(parent);
                rep.representation().binary_representation(ser_bin(bin, little));
                xr::ObjectVariant v; v.subscriber(rep); add("subscriber", v);
            }
            {
                xr::OBJK_DataWriter_Binary bin;
                bin.topic_id(xr::ObjectId{{0x00, 0x12}});
                if (full)
                {
                    xr::OBJK_DataWriter_Binary_Qos q;
                    q.base(endpoint_qos());
                    q.ownership_strength(7);
                    bin.qos(q);
                }
                xr::DATAWRITER_Representation rep;
                rep.publisher_id(xr::ObjectId{{0x00, 0x13}});
                rep.representation().binary_representation(ser_bin(bin, little));
                xr::ObjectVariant v; v.data_writer(rep); add("datawriter", v);
            }
            {
                xr::OBJK_DataReader_Binary bin;
                bin.topic_id(xr::ObjectId{{0x00, 0x12}});
                if (full)
                {
                    xr::OBJK_DataReader_Binary_Qos q;
                    q.base(endpoint_qos());
                    q.timebasedfilter_msec(50);
                    q.contentbased_filter(std::string("x > 1"));
                    bin.qos(std::move(q));   // Agent v3.0.2 defines only the rvalue overload here
                }
                xr::DATAREADER_Representation rep;
                rep.subscriber_id(xr::ObjectId{{0x00, 0x14}});
                rep.representation().binary_representation(ser_bin(bin, little));
                xr::ObjectVariant v; v.data_reader(rep); add("datareader", v);
            }
            {
                xr::OBJK_Requester_Binary bin;
                bin.service_name(std::string("rq/fuzz_service"));
                bin.request_type(std::string("ReqType"));
                bin.reply_type(std::string("RepType"));
                if (full) { bin.request_topic_name(std::string("rq/fuzzRequest")); bin.reply_topic_name(std::string("rr/fuzzReply")); }
                xr::REQUESTER_Representation rep;
                rep.participant_id(parent);
                rep.representation().binary_representation(ser_bin(bin, little));
                xr::ObjectVariant v; v.requester(rep); add("requester", v);
            }
            {
                xr::OBJK_Replier_Binary bin;
                bin.service_name(std::string("rq/fuzz_service"));
                bin.request_type(std::string("ReqType"));
                bin.reply_type(std::string("RepType"));
                if (full) { bin.request_topic_name(std::string("rq/fuzzRequest")); bin.reply_topic_name(std::string("rr/fuzzReply")); }
                xr::REPLIER_Representation rep;
                rep.participant_id(parent);
                rep.representation().binary_representation(ser_bin(bin, little));
                xr::ObjectVariant v; v.replier(rep); add("replier", v);
            }
        }
    }
    return out;
}

static int write_all(const char* dir)
{
    const std::vector<Seed> seeds = build_all();
    for (const Seed& s : seeds)
    {
        const std::string path = std::string(dir) + "/" + s.name + ".bin";
        FILE* fp = fopen(path.c_str(), "wb");
        if (!fp) { fprintf(stderr, "open failed: %s\n", path.c_str()); return 1; }
        const size_t n = fwrite(s.bytes.data(), 1, s.bytes.size(), fp);
        fclose(fp);
        if (n != s.bytes.size()) { fprintf(stderr, "short write: %s\n", path.c_str()); return 1; }
    }
    printf("wrote %zu binary-representation seeds to %s\n", seeds.size(), dir);
    return 0;
}
} // namespace seedgen

static int run_file(const char* path)
{
    FILE* fp = fopen(path, "rb");
    if (!fp) { fprintf(stderr, "open failed: %s\n", path); return 1; }
    fseek(fp, 0, SEEK_END); long n = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (n < 0) { fclose(fp); return 1; }
    std::vector<uint8_t> buf((size_t)n ? (size_t)n : 1);
    size_t got = fread(buf.data(), 1, (size_t)n, fp);
    fclose(fp);
    decode_once(buf.data(), got);
    return 0;
}

// Deterministic logic check: edge shapes that must not crash the HARNESS (an invalid XRCE
// message is the correct, safe early-return). Proves the harness + parse objects link and run.
static int selftest()
{
    const uint8_t empty[]    = { 0 };
    const uint8_t hdr_only[] = { 0x81, 0x00, 0x01, 0x00 };                         // header, no submessage
    const uint8_t with_sub[] = { 0x81, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0x00,  // CREATE_CLIENT subheader
                                 0xde, 0xad, 0xbe, 0xef };                          // 4-byte body
    struct { const uint8_t* p; size_t n; const char* name; } seeds[] = {
        { empty,    sizeof(empty),    "empty" },
        { hdr_only, sizeof(hdr_only), "header-only" },
        { with_sub, sizeof(with_sub), "header+create_client-sub" },
    };
    for (size_t i = 0; i < sizeof(seeds) / sizeof(seeds[0]); ++i)
    {
        decode_once(seeds[i].p, seeds[i].n);
        printf("  ok  %s\n", seeds[i].name);
    }
    // Positive control on stage-2 reach: every serialize-generated binary-representation seed
    // must be handed to its OBJK_*_Binary decoder AND decode cleanly. A harness that silently
    // stops at the opaque octet sequence fails here.
    const std::vector<seedgen::Seed> bin_seeds = seedgen::build_all();
    int failed = 0;
    for (const seedgen::Seed& s : bin_seeds)
    {
        const unsigned long attempts = g_bin_attempts, decoded = g_bin_decoded;
        decode_once(s.bytes.data(), s.bytes.size());
        if (g_bin_attempts != attempts + 1 || g_bin_decoded != decoded + 1)
        {
            printf("  FAIL %s (stage-2 attempted=%lu decoded=%lu)\n", s.name.c_str(),
                    g_bin_attempts - attempts, g_bin_decoded - decoded);
            ++failed;
        }
    }
    if (failed != 0)
    {
        printf("SELFTEST FAIL — %d of %zu binary-representation seeds did not reach/clear stage 2.\n",
                failed, bin_seeds.size());
        return 1;
    }
    printf("  ok  %zu binary-representation seeds reached and cleared the stage-2 decoders\n", bin_seeds.size());

    printf("SELFTEST PASS — agent parse harness decoded %zu edge seeds + %zu binary-representation seeds.\n",
           sizeof(seeds) / sizeof(seeds[0]), bin_seeds.size());
    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 2 || strcmp(argv[1], "--selftest") == 0) { return selftest(); }
    if (strcmp(argv[1], "--gen-seeds") == 0)
    {
        if (argc < 3) { fprintf(stderr, "usage: %s --gen-seeds <dir>\n", argv[0]); return 2; }
        return seedgen::write_all(argv[2]);
    }
    int rc = 0;
    for (int i = 1; i < argc; ++i) { rc |= run_file(argv[i]); }
    printf("replayed %d input(s) without a harness-side abort.\n", argc - 1);
    return rc;
}
#else
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    decode_once(data, size);
    return 0;
}
#endif // AGENT_FUZZ_STANDALONE
