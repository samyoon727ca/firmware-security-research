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
 * It uses U-Boot's own fuzz mechanism (CONFIG_FUZZ, FUZZ_TEST) so it can be
 * sent upstream as is. fuzz/uboot-fit/build.sh copies it into test/fuzz/ of
 * the pinned tree at build time; it is not built from this directory.
 *
 * Run: UBOOT_SB_FUZZ_TEST=fuzz_fit_check_format ./u-boot [libFuzzer args]
 * from a directory holding the control devicetree, FIT_FUZZ_CONTROL_DTB.
 */

#include <image.h>
#include <os.h>
#include <asm/global_data.h>
#include <stdio.h>
#include <linux/libfdt.h>
#include <linux/string.h>
#include <linux/types.h>
#include <test/fuzz.h>

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

static int fuzz_fit_check_format(const uint8_t *data, size_t size)
{
	/* The real size, so FIT_FULL_CHECK bounds the tree by the input. */
	if (fit_fuzz_load(data, size) && !fit_check_format(fit_fuzz_buf, size))
		fit_fuzz_config_verify(fit_fuzz_buf);

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
 *     and its kernel passes fit_image_verify() (its sha256 hash node);
 *  2. with one byte of the kernel payload flipped, is rejected. The config
 *     signature leaves out the "data" property (it covers each image's hash
 *     value instead), so the flip still passes fit_config_verify() and is
 *     caught by fit_image_verify(), as in fit_image_load(). Both results
 *     are asserted;
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

	return 0;
}
FUZZ_TEST(fuzz_fit_config_verify_check, 0);
