package br.edu.catolica.ms_auth.repository;

import br.edu.catolica.ms_auth.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {

    @Query(value = "SELECT * FROM tokens WHERE token = :token LIMIT 1", nativeQuery = true)
    Optional<Token> findByToken(@Param("token") String token);

    @Modifying
    @Query(value = "DELETE FROM tokens WHERE id_user = :userId", nativeQuery = true)
    void deleteAllByUserId(@Param("userId") Integer userId);

}