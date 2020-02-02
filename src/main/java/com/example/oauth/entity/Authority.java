package com.example.oauth.entity;

import java.io.Serializable;
import java.util.Objects;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.Table;
import org.springframework.security.core.GrantedAuthority;

@Entity
@Table(name = "authorities", schema = "public")
public class Authority implements GrantedAuthority, Serializable {

    private static final long serialVersionUID = 1L;

    @EmbeddedId
    private AuthorityCompositeKey compositeKey;

    public String getAuthority() {
        return this.compositeKey.authority;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Authority authority = (Authority) o;
        return compositeKey.equals(authority.compositeKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(compositeKey);
    }
}
