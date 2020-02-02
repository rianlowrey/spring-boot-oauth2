package com.example.oauth.entity;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
import javax.validation.constraints.NotBlank;

@Entity
@Table(name = "users", schema = "public", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"username"})
})
public class User implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @NotBlank
    @Column(name = "username", length = 50, nullable = false)
    private String username;

    @NotBlank
    @Column(name = "password", length = 256, nullable = false)
    private String password;

    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    @OneToMany(mappedBy = "user", fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    private List<Authority> authorities = Collections.emptyList();

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    public List<Authority> getAuthorities() {
        return this.authorities;
    }

    public boolean isEnabled() {
        return this.enabled;
    }
}
