// SPDX-License-Identifier: GPL-2.0+
/*
 * Local CI seed checks, oracle test hook, and confirm.sh verdict harness for
 * fuzz/uboot-fit/. Kept separate from fit_fuzz.c so fit_fuzz.c holds only the
 * upstreamable FUZZ_TEST(fuzz_fit_check_format) target.
 *
 * fuzz/uboot-fit/build.sh copies both files into test/fuzz/ of the pinned tree
 * and compiles fit_fuzz_ci.o, which pulls in fit_fuzz.c so the local checks
 * share its static buffer and helpers without exposing them in fit_fuzz.c.
 */

#include "fit_fuzz.c"

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
	fit_fuzz_buf[off] ^= 0x01;

	/* One signature byte: real RSA must reject it, the stub accept it. A pass leaves a line open. */
	ret = fdt_subnode_offset(fit_fuzz_buf, fit_conf_get_node(fit_fuzz_buf, NULL),
				 FIT_SIG_NODENAME);
	value = ret < 0 ? NULL : fdt_getprop(fit_fuzz_buf, ret, FIT_VALUE_PROP, &vlen);
	if (!value || vlen <= 0)
		fit_fuzz_fail("default configuration has no signature value", ret);
	fit_fuzz_buf[value - fit_fuzz_buf + vlen / 2] ^= 0x01;
	printf("\nfit_fuzz: signature byte flipped: %s by fit_config_verify()\n",
	       fit_fuzz_config_verify(fit_fuzz_buf) ? "rejected" : "accepted");
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
