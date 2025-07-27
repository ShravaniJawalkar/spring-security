package org.example.springsecurity.repository;

import org.example.springsecurity.repository.securitydao.UserAuth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserAuthRepository extends JpaRepository<UserAuth, Long> {
    @Query("select u from UserAuth u where u.username = :userName")
    Optional<UserAuth> findUserAuthByName(@Param("userName") String username);
}
