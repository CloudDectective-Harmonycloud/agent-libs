
kernelVersion = $(shell uname -r)
ErrorExit = exit 1

LIBS_IMAGE ?= kindlingproject/kernel-builder:latest

ifneq ($(shell cat /etc/os-release | grep Ubuntu | wc -l),0)
	KernelName = linux-headers-$(kernelVersion)
	CheckCommand = dpkg -l | grep $(KernelName)
	InstallCommand = sudo apt-get -y install $(KernelName)
else
	ifneq ($(shell cat /etc/os-release | grep CentOS | wc -l),0)
		KernelName = kernel-devel-$(kernelVersion)
		CheckCommand = yum list installed |grep $(KernelName)
		InstallCommand = sudo yum -y install $(KernelName)
	else
		KernelName = NotSupport
		CheckCommand = $(ErrorExit)
		InstallCommand = $(ErrorExit)
	endif
endif

.PHONY: all
all: dependencies agent-libs


.PHONY: builder-images
builder-images:
	@echo "Check dependencies images...";
	@if [ -z "$(shell docker images -q $(LIBS_IMAGE))" ]; then \
		echo "Downloading probe build image..."; \
		docker pull $(LIBS_IMAGE); \
	else \
		echo "Probe build image already exists"; \
	fi

.PHONY: kernel-headers
kernel-headers:
	@echo "Checking for kernel-headers...";
	@if [ "$(KernelName)" = "NotSupport" ]; then \
  		echo "$(KernelName) install kernel header,try install local"; \
		$(ErrorExit); \
	fi

	if [ -z "$(shell exit 1)" ]; then \
		echo "Downloading $(KernelName)..."; \
		$(InstallCommand); \
    	else \
    	echo "$(KernelName) already installed"; \
    fi

.PHONY: dependencies
dependencies: builder-images kernel-headers

.PHONY: build-libs
build-libs: ## build libs in docker with /lib/modules
	@echo "Building kindling libs..."
	@docker run \
		--env "ENV_HEADER_VERSION=$(kernelVersion)" \
		--rm -it \
		-v /usr:/host/usr \
		-v /lib/modules:/host/lib/modules \
		-v $(LIBS_SRC):/source \
		$(PROBE_IMAGE);

.PHONY: pack-libs
pack-libs:
	@echo "Packaging kindling libs...";
	@if [ ! -d "$(LIBS_SRC)/kindling-falcolib-probe/" ]; then \
    		echo "The packaged probe does not exist.try again"; \
    		exit 1; \
    else \
		cd $(LIBS_SRC) && \
		tar -cvzf kindling-falcolib-probe.tar.gz kindling-falcolib-probe/ \
	fi

.PHONY: agent-libs
agent-libs: build-libs pack-libs