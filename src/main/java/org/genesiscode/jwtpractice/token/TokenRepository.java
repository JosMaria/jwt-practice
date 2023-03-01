package org.genesiscode.jwtpractice.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Integer> {

    @Query(
    """
        SELECT t
        FROM Token t
        INNER JOIN User u
            ON t.user.id = u.id
        WHERE u.id = :userId AND (t.expired = FALSE OR t.revoked = FALSE)
    """)
    List<Token> findAllValidTokensByUser(@Param("userId") Integer userId);

    Optional<Token> findByToken(String token);
}
