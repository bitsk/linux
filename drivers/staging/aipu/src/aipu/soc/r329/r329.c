// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018-2021 Arm Technology (China) Co., Ltd. All rights reserved. */

/**
 * @file r329.c
 * Implementation of the R329 SoC operations
 */

#include <linux/clk.h>
#include <linux/reset.h>
#include <linux/irqreturn.h>
#include <linux/bitops.h>
#include "soc.h"
#include "r329.h"

#if (defined BUILD_PLATFORM_R329_MAINLINE)
static int r329_enable_clk(struct device *dev)
{
	struct clk *clk_aipu = NULL;
	struct clk *clk_bus_aipu = NULL;
	struct clk *clk_mbus_aipu = NULL;
	struct reset_control *rst = NULL;
	int ret;

	BUG_ON(!dev);

	clk_aipu = devm_clk_get(dev, "core");
	if (IS_ERR(clk_aipu)) {
		dev_err(dev, "clk_aipu get failed\n");
		return PTR_ERR(clk_aipu);
	}

	clk_bus_aipu = devm_clk_get(dev, "bus");
	if (IS_ERR(clk_bus_aipu)) {
		dev_err(dev, "clk_bus_aipu get failed\n");
		return PTR_ERR(clk_bus_aipu);
	}

	clk_mbus_aipu = devm_clk_get(dev, "mbus");
	if (IS_ERR(clk_mbus_aipu)) {
		dev_err(dev, "clk_mbus_aipu get failed\n");
		return PTR_ERR(clk_mbus_aipu);
	}

	rst = devm_reset_control_get(dev, NULL);
	if (IS_ERR(rst)) {
		dev_err(dev, "reset get failed\n");
		return PTR_ERR(rst);
	}

	ret = reset_control_deassert(rst);
	if (ret) {
		dev_err(dev, "reset deassert failed\n");
		return ret;
	}

	ret = clk_prepare_enable(clk_bus_aipu);
	if (ret) {
		dev_err(dev, "clk_bus_aipu enable failed\n");
		return ret;
	}

	ret = clk_prepare_enable(clk_mbus_aipu);
	if (ret) {
		dev_err(dev, "clk_bus_aipu enable failed\n");
		return ret;
	}

	ret = clk_prepare_enable(clk_aipu);
	if (ret) {
		dev_err(dev, "clk_aipu enable failed\n");
		return ret;
	}
	return 0;
}
#else
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
#endif


# if (defined BUILD_PLATFORM_R329_MAINLINE)
static int r329_disable_clk(struct device *dev)
{
	struct clk *clk_aipu = NULL;
	struct clk *clk_bus_aipu = NULL;
	struct clk *clk_mbus_aipu = NULL;
	struct reset_control *rst = NULL;

	clk_aipu = devm_clk_get(dev, "core");
	if (IS_ERR(clk_aipu))
		return -EBUSY;

	clk_bus_aipu = devm_clk_get(dev, "bus");
	if (IS_ERR(clk_bus_aipu))
		return -EBUSY;

	clk_mbus_aipu = devm_clk_get(dev, "mbus");
	if (IS_ERR(clk_mbus_aipu))
		return -EBUSY;

	rst = devm_reset_control_get(dev, NULL);
	if (IS_ERR(rst))
		return -EBUSY;

	clk_disable_unprepare(clk_aipu);
	clk_disable_unprepare(clk_mbus_aipu);
	clk_disable_unprepare(clk_bus_aipu);
	reset_control_assert(rst);
	return 0;
}
#else
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
#endif

static struct aipu_soc_operations r329_ops = {
	.enable_clk  = r329_enable_clk,
	.disable_clk = r329_disable_clk,
};

void aipu_soc_ops_register(struct aipu_soc_operations **ops)
{
	BUG_ON(!ops);
	*ops = &r329_ops;
}
