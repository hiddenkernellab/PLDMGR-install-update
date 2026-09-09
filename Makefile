PYTHON := python3
CC := /opt/ps5-payload-sdk/bin/prospero-clang
STRIP := /opt/ps5-payload-sdk/bin/prospero-strip

SDK := /opt/ps5-payload-sdk
TARGET := $(SDK)/target

# IMPORTANT:
# Payload Manager hides files whose name starts with "pldmgr"
# or contains "payload-manager" from the launch dashboard.
# Keep the visible app name in main.c as "PLDMGR Install & Update",
# but use a neutral ELF filename so it remains launchable.
ELF := HK-PLDMGR-Install-Update.elf
CA_HEADER := assets_cacert_pem.h

INCLUDES := -I. -I$(TARGET)/include

LIBS := \
	$(TARGET)/lib/libcurl.a \
	$(TARGET)/lib/libmbedtls.a \
	$(TARGET)/lib/libmbedx509.a \
	$(TARGET)/lib/libmbedcrypto.a \
	-L$(TARGET)/lib \
	-lpthread \
	-lSceNetCtl \
	-lSceUserService \
	-lSceSystemService \
	-lSceHttp2 \
	-lSceSsl \
	-lSceNet \
	-lSceSysmodule

CFLAGS := -Os -Wall -Wextra -ffunction-sections -fdata-sections $(INCLUDES)
LDFLAGS := -Wl,--gc-sections

all: $(ELF)

$(CA_HEADER):
	@echo "Downloading CA bundle..."
	wget -q -O cacert.pem https://curl.se/ca/cacert.pem
	$(PYTHON) tools/gen_asset.py cacert.pem $(CA_HEADER) hk_cacert_pem
	rm -f cacert.pem

$(ELF): main.c $(CA_HEADER)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ main.c $(LIBS)
	$(STRIP) $@
	@echo "Built: $(ELF)"

clean:
	rm -f $(ELF) PLDMGR-Install-Update.elf $(CA_HEADER) cacert.pem

.PHONY: all clean
