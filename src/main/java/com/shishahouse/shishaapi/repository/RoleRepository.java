package com.shishahouse.shishaapi.repository;

import com.shishahouse.shishaapi.models.ERole;
import com.shishahouse.shishaapi.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

  Optional<Role> findByName(ERole name);

}
