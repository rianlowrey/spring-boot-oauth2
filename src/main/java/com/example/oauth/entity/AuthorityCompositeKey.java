package com.example.oauth.entity;

import java.io.Serializable;
import java.util.Objects;
import javax.persistence.Embeddable;
import javax.validation.constraints.NotBlank;

@Embeddable
public class AuthorityCompositeKey implements Serializable {

    private static final long serialVersionUID = 1L;

    @NotBlank
    String username;

    @NotBlank
    String authority;

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AuthorityCompositeKey that = (AuthorityCompositeKey) o;
        return username.equals(that.username) &&
            authority.equals(that.authority);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, authority);
    }
}
