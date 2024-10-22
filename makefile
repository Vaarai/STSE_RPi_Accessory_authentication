#######################################
# Build configuration
#######################################
TOOLCHAIN_FOLDER := C:/SysGCC/raspberry/bin/
CC		:= ${TOOLCHAIN_FOLDER}arm-linux-gnueabihf-gcc.exe
LINKER	:= ${TOOLCHAIN_FOLDER}arm-linux-gnueabihf-ld.exe
DGB		:= ${TOOLCHAIN_FOLDER}arm-linux-gnueabihf-gdb.exe

BUILD_DIR		:= build
TARGET			:= ${BUILD_DIR}/accessory_authentication

FLAGS_WARNING	:= -Wall
FLAGS_DEBUG 	:= -g3

#######################################
# Ressources configuration
#######################################
COMPILER_INCLUDES	:= 	/opt/raspberry/arm-linux-gnueabihf/include
LINKER_LIBRARIES	:= 	/opt/raspberry/arm-linux-gnueabihf/lib \
						/opt/raspberry/arm-linux-gnueabihf/sysroot/usr/lib/arm-linux-gnueabihf \
						/opt/raspberry/arm-linux-gnueabihf/sysroot/lib

FOLDER_PLATFORMS 	:=	Platforms
FOLDER_STSELIB		:=	Middlewares/STSELib
FOLDER_MBEDTLS 		:=	Middlewares/MbedTLS

PROJECT_DEFINES 	:=	'MBEDTLS_CONFIG_FILE="config_mbedtls.h"'

PROJECT_SOURCES		:=	./main.c \
						$(shell find $(FOLDER_PLATFORMS) -regex '.*.c' -type f) \
						$(shell find $(FOLDER_STSELIB) -regex '.*.c' -type f) \
						$(shell find $(FOLDER_MBEDTLS)/tf-psa-crypto/drivers/builtin -regex '.*.c' -type f)

PROJECT_INCLUDES	:=	${FOLDER_STSELIB} \
						${FOLDER_PLATFORMS}/STSELib \
						${FOLDER_PLATFORMS}/Drivers \
						${FOLDER_PLATFORMS} \
						${FOLDER_MBEDTLS}/include \
						${FOLDER_PLATFORMS}/MbedTLS \
						${FOLDER_MBEDTLS}/tf-psa-crypto/drivers/builtin/include \
						${FOLDER_MBEDTLS}/tf-psa-crypto/core \
						${FOLDER_MBEDTLS}/tf-psa-crypto/include

OBJECTS := $(PROJECT_SOURCES:%.c=$(BUILD_DIR)/%.o)

#######################################
# Compiler / Linker flags
#######################################
CFLAGS	:=	$(FLAGS_WARNING) $(FLAGS_DEBUG) -MMD -MP \
			$(addprefix -I,${COMPILER_INCLUDES}) \
			$(addprefix -I,${PROJECT_INCLUDES}) \
			$(addprefix -D,${PROJECT_DEFINES})

LDFLAGS	:=	$(addprefix -L,$(LINKER_LIBRARIES)) \
			$(addprefix -I,${COMPILER_INCLUDES}) \
			$(addprefix -I,${PROJECT_INCLUDES}) \

#######################################
# Build rules
#######################################
all : $(TARGET)

# Link objects to generate the target
$(TARGET): $(OBJECTS)
	@echo -e "\n"${_CYAN}"Linking: $@"${_END}
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

# Compile c sources into objects
$(BUILD_DIR)/%.o: %.c makefile
	@echo -e "\n"${_CYAN}"Compiling: $< -> $@"${_END}
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Include all dependencies to track changes on sources & headers files
-include $(OBJECTS:.o=.d)

#######################################
# Utils
#######################################
# Terminal colors
_END	:=	"\033[0m"
_CYAN	:=	"\033[0;36m"

.PHONY: clean
clean:
	rm -r $(BUILD_DIR)
	rm $(TARGET)

help:
	@echo -e "Syntax : make [arguments]\n\
		arguments list :\n\
			all 	: 	Build the project (default rule)\n\
			clean 	: 	Remove the build directory and the output binary\n\
			help 	:	Show this message\n\
	"
