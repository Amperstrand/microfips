PYTEST := .venv/bin/pytest
ENVDIR := labgrid/config/envs
TESTDIR := labgrid/tests

.PHONY: test-all test-host test-esp32 test-esp32-uart test-esp32-l2cap test-esp32-ble test-stm32

test-all: test-host test-esp32 test-stm32

test-host:
	$(PYTEST) --lg-env $(ENVDIR)/linux-host.yaml $(TESTDIR)/test_fips_host.py -v

test-esp32: test-esp32-l2cap test-esp32-ble test-esp32-uart

test-esp32-uart:
	$(PYTEST) --lg-env $(ENVDIR)/esp32-d0wd-uart.yaml $(TESTDIR)/test_esp32_uart.py -v

test-esp32-l2cap:
	$(PYTEST) --lg-env $(ENVDIR)/esp32-d0wd-l2cap.yaml $(TESTDIR)/test_esp32_l2cap.py -v

test-esp32-ble:
	$(PYTEST) --lg-env $(ENVDIR)/esp32-d0wd-ble.yaml $(TESTDIR)/test_esp32_ble.py -v

test-stm32:
	$(PYTEST) $(TESTDIR)/test_stm32.py -v
