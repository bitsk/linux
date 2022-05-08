// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018-2021 Arm Technology (China) Co., Ltd. All rights reserved. */

/**
 * @file default.c
 * Implementation of the default SoC operations
 */

#include "soc.h"

static int default_enable_clk(struct device *dev)
{
	return 0;
}

static int default_disable_clk(struct device *dev)
{
	return 0;
}

static struct aipu_soc_operations default_ops = {
	.enable_clk  = default_enable_clk,
	.disable_clk = default_disable_clk,
};

void aipu_soc_ops_register(struct aipu_soc_operations **ops)
{
	BUG_ON(!ops);
	*ops = &default_ops;
}
