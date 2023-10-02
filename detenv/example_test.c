#include "detenv.h"

int main() {

	if (detenv_all_checks()) {
		printf("All checks passed successfully\n");
	}
	else {
		printf("Failed to pass all checks\n");
	}


	return 0;
}