/*
 * qtest function wrappers
 *
 * Copyright Red Hat Inc., 2019
 *
 * Authors:
 *  Alexander Bulekov   <alxndr@bu.edu>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "system/ioport.h"

#include "fuzz.h"

static bool serialize = true;

/*
 * Strong overrides for the libqtest I/O entry points. The default
 * (weak) definitions in tests/qtest/libqtest.c forward to qtest_*_real,
 * which still talks over the qtest socket. When this object is linked
 * into qemu-fuzz-* the strong versions below win, and we either
 * call into QEMU directly (in-process fuzzing) or fall back to the
 * socket impl (used by FUZZ_SERIALIZE_QTEST=1 reproducer-building mode).
 *
 * This replaces the previous -Wl,-wrap,qtest_* mechanism, which was
 * GNU-ld / ELF-lld only; weak overrides work on Mach-O too.
 */

uint8_t  qtest_inb_real(QTestState *s, uint16_t addr);
uint16_t qtest_inw_real(QTestState *s, uint16_t addr);
uint32_t qtest_inl_real(QTestState *s, uint16_t addr);
void     qtest_outb_real(QTestState *s, uint16_t addr, uint8_t value);
void     qtest_outw_real(QTestState *s, uint16_t addr, uint16_t value);
void     qtest_outl_real(QTestState *s, uint16_t addr, uint32_t value);
uint8_t  qtest_readb_real(QTestState *s, uint64_t addr);
uint16_t qtest_readw_real(QTestState *s, uint64_t addr);
uint32_t qtest_readl_real(QTestState *s, uint64_t addr);
uint64_t qtest_readq_real(QTestState *s, uint64_t addr);
void     qtest_writeb_real(QTestState *s, uint64_t addr, uint8_t value);
void     qtest_writew_real(QTestState *s, uint64_t addr, uint16_t value);
void     qtest_writel_real(QTestState *s, uint64_t addr, uint32_t value);
void     qtest_writeq_real(QTestState *s, uint64_t addr, uint64_t value);
void     qtest_memread_real(QTestState *s, uint64_t addr,
                            void *data, size_t size);
void     qtest_bufread_real(QTestState *s, uint64_t addr,
                            void *data, size_t size);
void     qtest_memwrite_real(QTestState *s, uint64_t addr,
                             const void *data, size_t size);
void     qtest_bufwrite_real(QTestState *s, uint64_t addr,
                             const void *data, size_t size);
void     qtest_memset_real(QTestState *s, uint64_t addr,
                           uint8_t patt, size_t size);

uint8_t qtest_inb(QTestState *s, uint16_t addr)
{
    if (!serialize) {
        return cpu_inb(addr);
    } else {
        return qtest_inb_real(s, addr);
    }
}

uint16_t qtest_inw(QTestState *s, uint16_t addr)
{
    if (!serialize) {
        return cpu_inw(addr);
    } else {
        return qtest_inw_real(s, addr);
    }
}

uint32_t qtest_inl(QTestState *s, uint16_t addr)
{
    if (!serialize) {
        return cpu_inl(addr);
    } else {
        return qtest_inl_real(s, addr);
    }
}

void qtest_outb(QTestState *s, uint16_t addr, uint8_t value)
{
    if (!serialize) {
        cpu_outb(addr, value);
    } else {
        qtest_outb_real(s, addr, value);
    }
}

void qtest_outw(QTestState *s, uint16_t addr, uint16_t value)
{
    if (!serialize) {
        cpu_outw(addr, value);
    } else {
        qtest_outw_real(s, addr, value);
    }
}

void qtest_outl(QTestState *s, uint16_t addr, uint32_t value)
{
    if (!serialize) {
        cpu_outl(addr, value);
    } else {
        qtest_outl_real(s, addr, value);
    }
}

uint8_t qtest_readb(QTestState *s, uint64_t addr)
{
    uint8_t value;
    if (!serialize) {
        address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED,
                            &value, 1);
        return value;
    } else {
        return qtest_readb_real(s, addr);
    }
}

uint16_t qtest_readw(QTestState *s, uint64_t addr)
{
    uint16_t value;
    if (!serialize) {
        address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED,
                            &value, 2);
        return value;
    } else {
        return qtest_readw_real(s, addr);
    }
}

uint32_t qtest_readl(QTestState *s, uint64_t addr)
{
    uint32_t value;
    if (!serialize) {
        address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED,
                            &value, 4);
        return value;
    } else {
        return qtest_readl_real(s, addr);
    }
}

uint64_t qtest_readq(QTestState *s, uint64_t addr)
{
    uint64_t value;
    if (!serialize) {
        address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED,
                            &value, 8);
        return value;
    } else {
        return qtest_readq_real(s, addr);
    }
}

void qtest_writeb(QTestState *s, uint64_t addr, uint8_t value)
{
    if (!serialize) {
        address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED,
                            &value, 1);
    } else {
        qtest_writeb_real(s, addr, value);
    }
}

void qtest_writew(QTestState *s, uint64_t addr, uint16_t value)
{
    if (!serialize) {
        address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED,
                            &value, 2);
    } else {
        qtest_writew_real(s, addr, value);
    }
}

void qtest_writel(QTestState *s, uint64_t addr, uint32_t value)
{
    if (!serialize) {
        address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED,
                            &value, 4);
    } else {
        qtest_writel_real(s, addr, value);
    }
}

void qtest_writeq(QTestState *s, uint64_t addr, uint64_t value)
{
    if (!serialize) {
        address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED,
                            &value, 8);
    } else {
        qtest_writeq_real(s, addr, value);
    }
}

void qtest_memread(QTestState *s, uint64_t addr, void *data, size_t size)
{
    if (!serialize) {
        address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, data,
                           size);
    } else {
        qtest_memread_real(s, addr, data, size);
    }
}

void qtest_bufread(QTestState *s, uint64_t addr, void *data, size_t size)
{
    if (!serialize) {
        address_space_read(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED, data,
                           size);
    } else {
        qtest_bufread_real(s, addr, data, size);
    }
}

void qtest_memwrite(QTestState *s, uint64_t addr, const void *data,
                    size_t size)
{
    if (!serialize) {
        address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED,
                            data, size);
    } else {
        qtest_memwrite_real(s, addr, data, size);
    }
}

void qtest_bufwrite(QTestState *s, uint64_t addr,
                    const void *data, size_t size)
{
    if (!serialize) {
        address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED,
                            data, size);
    } else {
        qtest_bufwrite_real(s, addr, data, size);
    }
}

void qtest_memset(QTestState *s, uint64_t addr,
                  uint8_t patt, size_t size)
{
    void *data;
    if (!serialize) {
        data = malloc(size);
        memset(data, patt, size);
        address_space_write(first_cpu->as, addr, MEMTXATTRS_UNSPECIFIED,
                            data, size);
        free(data);
    } else {
        qtest_memset_real(s, addr, patt, size);
    }
}

void fuzz_qtest_set_serialize(bool option)
{
    serialize = option;
}
