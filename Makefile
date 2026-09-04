PYTEST := python3 -m pytest
HIL_DIR := tools/hil
ALLURE_RESULTS := $(HIL_DIR)/results/allure

# HIL framework (issue #191 - bolty-rs pattern over the shared bench).
# Registry: fips-lab/fips_lab/boards.toml is the single safety contract
# (flash/observe ops). Protocol-level scenarios live in fips-lab; these
# targets own deployment health: preflight, build+flash+boot smoke,
# ledger (results/history.jsonl), Allure.
#
# The old labgrid/ harness is DEPRECATED (see labgrid/DEPRECATED.md) -
# its targets are kept as loud pointers only.

.PHONY: test-hil hil-preflight hil-status hil-unit labgrid-place hil-report \
        test-all test-host test-esp32 test-esp32-uart test-esp32-l2cap \
        test-esp32-ble test-stm32

test-hil:
	mkdir -p $(HIL_DIR)/results
	$(PYTEST) $(HIL_DIR)/tests -m "hardware" -v \
	  --alluredir=$(ALLURE_RESULTS)/$$(date +%Y%m%d-%H%M%S)

hil-unit:
	$(PYTEST) $(HIL_DIR)/tests -m "not hardware" -v

hil-preflight:
	cd $(HIL_DIR) && python3 -m hil.preflight

hil-status:
	@systemctl is-active labgrid-exporter-microfips 2>/dev/null \
	  || echo "exporter-microfips: not-running"
	@labgrid-client -x 192.168.13.221:20408 resources 2>/dev/null \
	  | grep -i "$(shell hostname)" || echo "no resources on coordinator"
	@echo "bench flock: $$([ -f /tmp/amperstrand-bench.lock ] \
	  && cat /tmp/amperstrand-bench.lock | tr '\n' ' ' \
	  || echo free)"
	@echo "board state (labgrid per-board places):"
	@for b in s3-lab atom-a atom-b cyd stm32; do \
	  echo "  $$b: $$(labgrid-client -x 192.168.13.221:20408 \
	    -p microfips-$$b show 2>/dev/null \
	    | sed -n 's/^  tags: //p' | tr ',' ' ' || echo '?')"; \
	done
	@echo "role ledger (last 3):"
	@tail -3 $(HIL_DIR)/results/board-roles.jsonl 2>/dev/null || echo "  (empty)"

labgrid-place:
	bash $(HIL_DIR)/labgrid-place.sh

hil-report:
	@latest=$$(ls -dt $(ALLURE_RESULTS)/* 2>/dev/null | head -1); \
	if [ -n "$$latest" ]; then \
	  allure generate -o $(HIL_DIR)/results/allure-html "$$latest" \
	  && echo "report: $(HIL_DIR)/results/allure-html/index.html"; \
	else echo "no allure results yet - run make test-hil"; fi

# DEPRECATED: old labgrid/ harness (broken .venv path, stale src2
# hardcodes, superseded by fips-lab + tools/hil). Kept as pointers.

test-all test-host test-esp32 test-esp32-uart test-esp32-l2cap test-esp32-ble test-stm32:
	@echo "DEPRECATED: labgrid/ harness is retired (see labgrid/DEPRECATED.md)."
	@echo "  hardware smoke : make test-hil"
	@echo "  protocol depth : fips-lab  (make -C ../fips-lab test-labgrid)"
	@exit 1
