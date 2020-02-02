package com.example.oauth.entity;

import java.io.Serializable;
import java.util.Objects;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;
import org.springframework.security.core.GrantedAuthority;

@Entity
@Table(name = "authorities", schema = "public")
public class Authority implements GrantedAuthority, Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @ManyToOne(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinColumn(name = "username", nullable = false)
    private User user;

    @NotBlank
    @Column(name = "authority", nullable = false)
    private String authority;

    public User getUser() {
        return this.user;
    }

    public String getAuthority() {
        return this.authority;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Authority authority1 = (Authority) o;
        return user.equals(authority1.user) &&
            authority.equals(authority1.authority);
    }

    @Override
    public int hashCode() {
        return Objects.hash(user, authority);
    }
}
