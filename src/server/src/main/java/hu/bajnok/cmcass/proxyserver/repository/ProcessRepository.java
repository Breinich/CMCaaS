package hu.bajnok.cmcass.proxyserver.repository;

import hu.bajnok.cmcass.proxyserver.model.Process;
import hu.bajnok.cmcass.proxyserver.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface ProcessRepository extends JpaRepository<Process, Integer> {
    Optional<Process> findByKeyAndUser(String key, User user);

    void deleteByKeyAndUser(String key, User user);

    @Query("SELECT p.id FROM Process p")
    List<Integer> findAllProcessIds();
}
