ARCHS ?= arm64
target ?= iphone:latest:11.0
CFLAGS = -Iinclude
include $(THEOS)/makefiles/common.mk

TOOL_NAME = bin
bin_FILES = main.m

include $(THEOS_MAKE_PATH)/tool.mk
