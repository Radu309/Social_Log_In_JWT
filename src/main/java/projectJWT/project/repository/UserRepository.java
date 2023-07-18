package projectJWT.project.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import projectJWT.project.model.User;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {
    Optional<User> findByEmail(String email);
}
