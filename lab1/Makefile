CC = cc
CPPFLAGS += -D_DEFAULT_SOURCE -Isrc/include
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -g -O0
LDLIBS += -lpcap
OBJECTS = build/device.o build/packetio.o build/apps/lab1_demo.o

.PHONY: all clean
all: build/lab1_demo

build/lab1_demo: $(OBJECTS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

build/%.o: src/%.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(OBJECTS:.o=.d)

clean:
	rm -rf build
