package com.example.ss_2022_c2_e1.repositories;

import com.example.ss_2022_c2_e1.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    // the jpa will work without the query, it's just there as my preference, so that everything is explicit
    Optional<User> findUserByUsername(String username);
}
