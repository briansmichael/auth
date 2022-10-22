package com.starfireaviation.auth.model;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SAUserRepository extends JpaRepository<SAUser,Long> {

    SAUser findByEmail(String email);
}
