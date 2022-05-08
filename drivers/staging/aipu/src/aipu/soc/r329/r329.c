// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018-2021 Arm Technology (China) Co., Ltd. All rights reserved. */

/**
 * @file r329.c
 * Implementation of the R329 SoC operations
 */

#include <linux/clk.h>
#include "soc.h"
#include "r329.h"

static int r329_enable_clk(struct device *dev)
{
	struct clk *clk_pll_aipu = NULL;
	struct clk *clk_aipu = NULL;
	struct clk *clk_aipu_slv = NULL;
	struct device_node *dev_node = NULL;

	BUG_ON(!dev);
	dev_node = dev->of_node;

	clk_pll_aipu = of_clk_get(dev_node, 0);
	if (IS_ERR_OR_NULL(clk_pll_aipu)) {
		dev_err(dev, "clk_pll_aipu get failed\n");
		return PTR_ERR(clk_pll_aipu);
	}

	clk_aipu = of_clk_get(dev_node, 1);
	if (IS_ERR_OR_NULL(clk_aipu)) {
		dev_err(dev, "clk_aipu get failed\n");
		return PTR_ERR(clk_aipu);
	}

	clk_aipu_slv = of_clk_get(dev_node, 2);
	if (IS_ERR_OR_NULL(clk_aipu_slv)) {
		dev_err(dev, "clk_pll_aipu get failed\n");
		return PTR_ERR(clk_aipu_slv);
	}

	if (clk_set_parent(clk_aipu, clk_pll_aipu)) {
		dev_err(dev, "set clk_aipu parent fail\n");
		return -EBUSY;
	}

	if (clk_set_rate(clk_aipu, R329_AIPU_CLOCK_RATE)) {
		dev_err(dev, "set clk_aipu rate fail\n");
		return -EBUSY;
	}

	if (clk_prepare_enable(clk_aipu_slv)) {
		dev_err(dev, "clk_aipu_slv enable failed\n");
		return -EBUSY;
	}

	if (clk_prepare_enable(clk_aipu)) {
		dev_err(dev, "clk_aipu enable failed\n");
		return -EBUSY;
	}

	dev_info(dev, "enable r329 AIPU clock done\n");
	return 0;
}

static int r329_disable_clk(struct device *dev)
{
	struct clk *clk_aipu = NULL;
	struct clk *clk_aipu_slv = NULL;
	struct device_node *dev_node = NULL;

	BUG_ON(!dev);
	dev_node = dev->of_node;

	clk_aipu_slv = of_clk_get(dev_node, 2);
	if (clk_aipu_slv)
		clk_disable_unprepare(clk_aipu_slv);

	clk_aipu = of_clk_get(dev_node, 1);
	if (clk_aipu)
		clk_disable_unprepare(clk_aipu);

	dev_info(dev, "disable r329 AIPU clock done\n");
	return 0;
}

static struct aipu_soc_operations r329_ops = {
	.enable_clk  = r329_enable_clk,
	.disable_clk = r329_disable_clk,
};

void aipu_soc_ops_register(struct aipu_soc_operations **ops)
{
	BUG_ON(!ops);
	*ops = &r329_ops;
}
