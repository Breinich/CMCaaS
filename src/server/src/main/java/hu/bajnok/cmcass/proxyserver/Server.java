package hu.bajnok.cmcass.proxyserver;

import static org.springframework.boot.SpringApplication.run;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class Server {
  public static void main(String[] args) {
    run(Server.class, args);
  }
}
