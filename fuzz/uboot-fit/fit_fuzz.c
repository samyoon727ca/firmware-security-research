// SPDX-License-Identifier: GPL-2.0+
/*
 * FIT format-check fuzz target for the U-Boot sandbox.
 *
 * fit_check_format() is the first thing U-Boot runs on a FIT it has loaded,
 * before any signature is checked, so every byte it reads is attacker-chosen.
 * This target hands it one fuzzer input per call.
 *
 * It uses U-Boot's own fuzz mechanism (CONFIG_FUZZ, FUZZ_TEST) so it can be
 * sent upstream as is. fuzz/uboot-fit/build.sh copies it into test/fuzz/ of
 * the pinned tree at build time; it is not built from this directory.
 *
 * Run: UBOOT_SB_FUZZ_TEST=fuzz_fit_check_format ./u-boot [libFuzzer args]
 */

#include <image.h>
#include <os.h>
#include <stdio.h>
#include <linux/libfdt.h>
#include <linux/string.h>
#include <linux/types.h>
#include <test/fuzz.h>

/* Inputs above this size are skipped; a real FIT header plus tree fits. */
#define FIT_FUZZ_MAX_LEN	(64 * 1024)

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

static int fuzz_fit_check_format(const uint8_t *data, size_t size)
{
	/* The real size, so FIT_FULL_CHECK bounds the tree by the input. */
	if (fit_fuzz_load(data, size))
		fit_check_format(fit_fuzz_buf, size);

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
