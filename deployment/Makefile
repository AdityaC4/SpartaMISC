
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

all: host_secrets
	echo "#define SECRET 1234" > global_secrets.h

host_secrets:
	poetry install
	poetry run python gen_host_secrets.py

clean:
	rm -f global_secrets.h
