/* Copyright 2020 UPMEM. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HW_DPU_SYSFS_H
#define HW_DPU_SYSFS_H

#include <stdio.h>

#include <dpu_description.h>

#define DPU_INVALID_RANK_INDEX 255

struct dpu_rank_fs {
    char rank_path[128];
    int fd_rank;
    int fd_dax;

    struct udev_device *udev;
    struct udev_device *udev_dax;
};

uint8_t
dpu_sysfs_get_nb_physical_ranks();

int
dpu_sysfs_get_available_rank(const char *rank_path, struct dpu_rank_fs *rank_fs);
void
dpu_sysfs_free_rank(struct dpu_rank_fs *rank_fs);

uint64_t
dpu_sysfs_get_region_size(struct dpu_rank_fs *rank_fs);
uint8_t
dpu_sysfs_get_rank_id(struct dpu_rank_fs *rank_fs);
uint8_t
dpu_sysfs_get_channel_id(struct dpu_rank_fs *rank_fs);
uint8_t
dpu_sysfs_get_dpu_chip_id(struct dpu_rank_fs *rank_fs);
uint8_t
dpu_sysfs_get_backend_id(struct dpu_rank_fs *rank_fs);
uint8_t
dpu_sysfs_get_nb_ci(struct dpu_rank_fs *rank_fs);
struct udev_list_entry *
get_udev_entry_for_index(struct dpu_rank_fs *rank_fs, uint32_t selected_index);
uint8_t
dpu_sysfs_get_ci_mask(struct dpu_rank_fs *rank_fs);
uint8_t
dpu_sysfs_get_nb_dpus_per_ci(struct dpu_rank_fs *rank_fs);
uint32_t
dpu_sysfs_get_mram_size(struct dpu_rank_fs *rank_fs);
uint64_t
dpu_sysfs_get_capabilities(struct dpu_rank_fs *rank_fs);
int
dpu_sysfs_set_reset_ila(struct dpu_rank_fs *rank_fs, uint8_t val);

uint32_t
dpu_sysfs_get_activate_ila(struct dpu_rank_fs *rank_fs);
int
dpu_sysfs_set_activate_ila(struct dpu_rank_fs *rank_fs, uint8_t val);

uint32_t
dpu_sysfs_get_activate_filtering_ila(struct dpu_rank_fs *rank_fs);
int
dpu_sysfs_set_activate_filtering_ila(struct dpu_rank_fs *rank_fs, uint8_t val);

uint32_t
dpu_sysfs_get_activate_mram_bypass(struct dpu_rank_fs *rank_fs);
int
dpu_sysfs_set_activate_mram_bypass(struct dpu_rank_fs *rank_fs, uint8_t val);

uint32_t
dpu_sysfs_get_mram_refresh_emulation_period(struct dpu_rank_fs *rank_fs);
int
dpu_sysfs_set_mram_refresh_emulation_period(struct dpu_rank_fs *rank_fs, uint32_t val);

int
dpu_sysfs_set_inject_faults(struct dpu_rank_fs *rank_fs, uint8_t val);

int
dpu_sysfs_get_hardware_chip_id(uint8_t *chip_id);

int
dpu_sysfs_get_hardware_description(dpu_description_t description, uint8_t *capabilities_mode);

int
dpu_sysfs_get_kernel_module_version(unsigned int *major, unsigned int *minor);

uint8_t
dpu_sysfs_get_rank_index(struct dpu_rank_fs *rank_fs);

int
dpu_sysfs_get_numa_node(struct dpu_rank_fs *rank_fs);

const char *
dpu_sysfs_get_byte_order(struct dpu_rank_fs *rank_fs);

#endif /* HW_DPU_SYSFS_H */
