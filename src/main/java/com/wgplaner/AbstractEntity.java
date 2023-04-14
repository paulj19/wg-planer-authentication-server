package com.wgplaner;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.ZonedDateTime;

@Getter
@MappedSuperclass
@SuperBuilder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AbstractEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    protected Long id;

    @Version
    @Column(name = "version")
    protected Long version;

    @CreationTimestamp
    @Column(name = "creation_date", nullable = false)
    protected ZonedDateTime creationDate;

    @UpdateTimestamp
    @Column(name = "modification_date", nullable = false)
    protected ZonedDateTime modificationDate;

    @PrePersist
    void prePersist() {
        modificationDate = creationDate = ZonedDateTime.now();
    }

    @PreUpdate
    void preUpdate() {
        modificationDate = ZonedDateTime.now();
    }
}
