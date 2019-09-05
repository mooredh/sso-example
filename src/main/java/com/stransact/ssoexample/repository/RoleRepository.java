package com.stransact.ssoexample.repository;

import com.stransact.ssoexample.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * The interface Role repository.
 *
 * @author Dagogo Hart Moore
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
