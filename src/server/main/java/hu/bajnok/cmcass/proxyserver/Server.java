package hu.bajnok.cmcass.proxyserver;

import org.springframework.boot.autoconfigure.SpringBootApplication;

import static org.springframework.boot.SpringApplication.run;

@SpringBootApplication
public class Server {
    public static void main(String[] args) {
        run(Server.class, args);
    }
}
