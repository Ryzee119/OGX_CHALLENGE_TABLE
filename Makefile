XBE_TITLE = XBOX_CHALLENGES
GEN_XISO = $(XBE_TITLE).iso
SRCS = $(CURDIR)/main.c
NXDK_DIR ?= $(CURDIR)/../..
NXDK_SDL = y
include $(NXDK_DIR)/Makefile
