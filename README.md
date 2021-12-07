# Project 3

### About

---

This program allows for execution for several methods, including creating and validating the integrity of both a certificate
as well as a certificate revocation list. It allows for sending a validating Certificates over sockets, and the traversal of the tree
of certs for determining trust.

### Execution

---

To execute this program:

    * Execute the bash script to compile with ./CertsCompile.sh
    * Execute the program using ./a.out, and follow the menu prompts

To execute the sockets demonstration:

    * Open two terminals. Navigate to the Client folder in one, and the Server folder in the other.
    * Run ./ServerCompile.sh an ./ClientCompile.sh in each respective terminal.
    * Execute the server using ./Server, followed by the Client using ./Client
    * Follow the menu prompts.