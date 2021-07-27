package sagekhw.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sagekhw.jwt.entity.Authority;

public interface AuthorityRepository extends JpaRepository<Authority, String> {
}