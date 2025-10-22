package hu.bajnok.repository;

import hu.bajnok.model.Process;
import hu.bajnok.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ProcessRepository extends JpaRepository<Process, Integer> {
    Optional<Process> findByKeyAndUser(String key, User user);

    void deleteByKeyAndUser(String key, User user);

    List<Process> findAllByUser(User user);

    Optional<Process> findByKey(String key);

    List<Integer> findAllProcessIds();
}
