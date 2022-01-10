diff --git a/arch/arm/boot/dts/qcom/msm-pm660.dtsi b/arch/arm/boot/dts/qcom/msm-pm660.dtsi
index 460e7e76ac4d..fc2b765860d7 100644
--- a/arch/arm/boot/dts/qcom/msm-pm660.dtsi
+++ b/arch/arm/boot/dts/qcom/msm-pm660.dtsi
@@ -630,28 +630,70 @@
 		#size-cells = <0>;
 
 		pm660_haptics: qcom,haptic@c000 {
-			compatible = "qcom,qpnp-haptic";
+			compatible = "qcom,pm660-haptics";
 			reg = <0xc000 0x100>;
 			interrupts = <0x1 0xc0 0x0 IRQ_TYPE_EDGE_BOTH>,
 				     <0x1 0xc0 0x1 IRQ_TYPE_EDGE_BOTH>;
-			interrupt-names = "sc-irq", "play-irq";
-			qcom,pmic-revid = <&pm660_revid>;
-			qcom,pmic-misc = <&pm660_misc>;
-			qcom,misc-clk-trim-error-reg = <0xf3>;
+			interrupt-names = "hap-sc-irq", "hap-play-irq";
 			qcom,actuator-type = "lra";
-			qcom,play-mode = "direct";
 			qcom,vmax-mv = <3200>;
-			qcom,ilim-ma = <800>;
-			qcom,wave-shape = "square";
-			qcom,wave-play-rate-us = <6667>;
-			qcom,int-pwm-freq-khz = <505>;
-			qcom,sc-deb-cycles = <8>;
-			qcom,en-brake;
-			qcom,brake-pattern = [03 03 00 00];
-			qcom,lra-high-z = "opt0";
-			qcom,lra-auto-res-mode = "qwd";
-			qcom,lra-calibrate-at-eop = <0>;
-			qcom,correct-lra-drive-freq;
+			qcom,play-rate-us = <6667>;
+			qcom,lra-resonance-sig-shape = "sine";
+			qcom,lra-auto-resonance-mode = "qwd";
+			qcom,lra-allow-variable-play-rate;
+
+			wf_0 {
+				/* CLICK */
+				qcom,effect-id = <0>;
+				qcom,wf-vmax-mv = <3600>;
+				qcom,wf-pattern = [3e 3e 3e];
+				qcom,wf-play-rate-us = <6667>;
+				qcom,wf-brake-pattern = [01 00 00 00];
+				qcom,lra-auto-resonance-disable;
+			};
+			wf_1 {
+				/* DOUBLE CLICK */
+				qcom,effect-id = <1>;
+				qcom,wf-vmax-mv = <3600>;
+				qcom,wf-pattern = [7e 7e 02 02 02 02 02 02];
+				qcom,wf-play-rate-us = <7143>;
+				qcom,wf-repeat-count = <2>;
+				qcom,wf-s-repeat-count = <1>;
+				qcom,lra-auto-resonance-disable;
+			};
+			wf_2 {
+				/* TICK */
+				qcom,effect-id = <2>;
+				qcom,wf-vmax-mv = <3600>;
+				qcom,wf-pattern = [7e 7e];
+				qcom,wf-play-rate-us = <4000>;
+				qcom,lra-auto-resonance-disable;
+			};
+			wf_3 {
+				/* THUD */
+				qcom,effect-id = <3>;
+				qcom,wf-vmax-mv = <3600>;
+				qcom,wf-pattern = [7e 7e 7e];
+				qcom,wf-play-rate-us = <6667>;
+				qcom,lra-auto-resonance-disable;
+			};
+			wf_4 {
+				/* POP */
+				qcom,effect-id = <4>;
+				qcom,wf-vmax-mv = <3600>;
+				qcom,wf-pattern = [7e 7e];
+				qcom,wf-play-rate-us = <5000>;
+				qcom,lra-auto-resonance-disable;
+			};
+			wf_5 {
+				/* HEAVY CLICK */
+				qcom,effect-id = <5>;
+				qcom,wf-vmax-mv = <3600>;
+				qcom,wf-pattern = [7e 7e 7e];
+				qcom,wf-play-rate-us = <6667>;
+				qcom,wf-brake-pattern = [03 00 00 00];
+				qcom,lra-auto-resonance-disable;
+			};
 		};
 	};
 };
diff --git a/arch/arm64/configs/lavender-perf_defconfig b/arch/arm64/configs/lavender-perf_defconfig
index a3f7f5259365..3e10f2db1111 100644
--- a/arch/arm64/configs/lavender-perf_defconfig
+++ b/arch/arm64/configs/lavender-perf_defconfig
@@ -4008,7 +4008,8 @@ CONFIG_ARM_SMMU=y
 # CONFIG_MSM_PFE_WA is not set
 CONFIG_QCOM_COMMON_LOG=y
 CONFIG_MSM_SMEM=y
-CONFIG_QPNP_HAPTIC=y
+# CONFIG_QPNP_HAPTIC is not set
+CONFIG_INPUT_QTI_HAPTICS=y
 CONFIG_QPNP_PBS=y
 CONFIG_MSM_SMD=y
 # CONFIG_MSM_SMD_DEBUG is not set
diff --git a/drivers/input/misc/Kconfig b/drivers/input/misc/Kconfig
index 686f33b70ac1..bab0081c2c4e 100644
--- a/drivers/input/misc/Kconfig
+++ b/drivers/input/misc/Kconfig
@@ -170,6 +170,15 @@ config INPUT_QPNP_POWER_ON
 	  reporting the change in status of the KPDPWR_N line (connected to the
 	  power-key) as well as reset features.
 
+config INPUT_QTI_HAPTICS
+	tristate "Haptics support for QTI PMIC"
+	depends on MFD_SPMI_PMIC
+	help
+	  This option enables device driver support for the haptics peripheral
+	  found on Qualcomm Technologies, Inc. PMICs.  The haptics peripheral
+	  is capable of driving both LRA and ERM vibrators.  This module provides
+	  haptic feedback for user actions such as a long press on the touch screen.
+
 config INPUT_SPARCSPKR
 	tristate "SPARC Speaker support"
 	depends on PCI && SPARC64
diff --git a/drivers/input/misc/Makefile b/drivers/input/misc/Makefile
index 71744ee21a31..f653a3512083 100644
--- a/drivers/input/misc/Makefile
+++ b/drivers/input/misc/Makefile
@@ -58,6 +58,7 @@ obj-$(CONFIG_INPUT_PM8941_PWRKEY)	+= pm8941-pwrkey.o
 obj-$(CONFIG_INPUT_PM8XXX_VIBRATOR)	+= pm8xxx-vibrator.o
 obj-$(CONFIG_INPUT_PMIC8XXX_PWRKEY)	+= pmic8xxx-pwrkey.o
 obj-$(CONFIG_INPUT_QPNP_POWER_ON)	+= qpnp-power-on.o
+obj-$(CONFIG_INPUT_QTI_HAPTICS)		+= qti-haptics.o
 obj-$(CONFIG_INPUT_POWERMATE)		+= powermate.o
 obj-$(CONFIG_INPUT_PWM_BEEPER)		+= pwm-beeper.o
 obj-$(CONFIG_INPUT_RB532_BUTTON)	+= rb532_button.o
