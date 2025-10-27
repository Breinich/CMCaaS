package hu.bajnok.cmcass.proxyserver;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

import static org.springframework.boot.SpringApplication.run;

@SpringBootApplication
@EnableAsync
public class Server {
    public static void main(String[] args) {
        run(Server.class, args);
    }
}
