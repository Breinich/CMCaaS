package hu.bajnok.cmcass.proxyserver.repository;

import hu.bajnok.cmcass.proxyserver.model.Process;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.zip.ZipFile;

public interface ProcessRepository extends JpaRepository<Process, Integer> {
    void deleteByKeyAndUser_Id(String key, Long userId);

    Optional<Process> findByKeyAndUser_Id(String key, Long userId);

    @Query("SELECT p.port FROM Process p")
    List<Integer> findAllProcessPorts();
}
