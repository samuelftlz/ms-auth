package br.edu.catolica.ms_auth.repository;

import br.edu.catolica.ms_auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    @Query(value = "SELECT * FROM users WHERE email = :email LIMIT 1", nativeQuery = true)
    Optional<User> findByEmail(@Param("email") String email);

    @Query(value = "SELECT * FROM users WHERE email = :email AND doc_number = :docNumber LIMIT 1", nativeQuery = true)
    Optional<User> findByEmailAndDocNumber(@Param("email") String email, @Param("docNumber") String docNumber);
}