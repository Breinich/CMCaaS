package hu.bajnok.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Entity
@Table(name = "processes")
public class Process {
    @Id
    private int id;

    @Column(nullable = false)
    private String key;

    @JoinTable
    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id", nullable = false)
    private User user;
}
