# Build outputs are kept separate from tracked legacy binaries.
.RECIPEPREFIX = >

CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic
LDLIBS_T = -pthread

BUILD_DIR = build
CORE_BIN = $(BUILD_DIR)/radar_core
TEST_BIN = $(BUILD_DIR)/test_engine

IMGUI_DIR ?= third_party/imgui
IMGUI_SRC = $(IMGUI_DIR)/imgui.cpp $(IMGUI_DIR)/imgui_draw.cpp $(IMGUI_DIR)/imgui_tables.cpp \
            $(IMGUI_DIR)/imgui_widgets.cpp $(IMGUI_DIR)/backends/imgui_impl_glfw.cpp \
            $(IMGUI_DIR)/backends/imgui_impl_opengl3.cpp

.PHONY: all core test gui clean

all: core

core: $(CORE_BIN)

$(CORE_BIN): src/radar_core.cpp json.hpp
> mkdir -p $(BUILD_DIR)
> $(CXX) $(CXXFLAGS) -I. -o $@ $< $(LDLIBS_T)

test: $(TEST_BIN) $(CORE_BIN)
> ./$(TEST_BIN)

$(TEST_BIN): tests/test_engine_client.cpp src/engine_client.hpp json.hpp
> mkdir -p $(BUILD_DIR)
> $(CXX) $(CXXFLAGS) -I. -o $@ $< $(LDLIBS_T)

gui: radar_gui.cpp
> $(CXX) $(CXXFLAGS) -I$(IMGUI_DIR) -I$(IMGUI_DIR)/backends -o radar_gui radar_gui.cpp \
>   $(IMGUI_SRC) $$(pkg-config --cflags --libs glfw3) -lGL $(LDLIBS_T)

clean:
> rm -f $(CORE_BIN) $(TEST_BIN)
> rmdir $(BUILD_DIR) 2>/dev/null || true
