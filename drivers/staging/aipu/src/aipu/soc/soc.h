/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018-2021 Arm Technology (China) Co., Ltd. All rights reserved. */

/**
 * @file soc.h
 * Header of the SoC common operations
 */

#ifndef __SOC_H__
#define __SOC_H__

#include <linux/device.h>

/**
 * struct aipu_soc_operations - a struct contains SoC operation methods
 *
 * @enable_clk:   enable clock
 * @disable_clk:  disable clock
 */
struct aipu_soc_operations {
	int (*enable_clk)(struct device *dev);
	int (*disable_clk)(struct device *dev);
};

/**
 * @brief register AIPU SoC operations
 *        SoC vendor should implement the specific soc_operations and register it
 *
 * @param ops: operation pointer
 *
 * @return 0 on success; others on failure;
 */
void aipu_soc_ops_register(struct aipu_soc_operations **ops);

#endif /* __SOC_H__ */
