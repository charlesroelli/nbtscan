#if !defined ERRORS_H
#define ERRORS_H

#define err_die(error, quiet) if(!quiet) {perror(error); exit(1);};

#define err_print(error, quiet) if(!quiet) perror(error);

#endif /* ERRORS_H */
