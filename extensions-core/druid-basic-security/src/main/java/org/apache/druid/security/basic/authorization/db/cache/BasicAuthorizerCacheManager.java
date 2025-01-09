/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.druid.security.basic.authorization.db.cache;

import com.google.common.collect.ImmutableSet;
import org.apache.druid.query.filter.EqualityFilter;
import org.apache.druid.query.filter.FalseDimFilter;
import org.apache.druid.query.policy.NoRestrictionPolicy;
import org.apache.druid.query.policy.Policy;
import org.apache.druid.query.policy.RowFilterPolicy;
import org.apache.druid.security.basic.BasicAuthUtils;
import org.apache.druid.security.basic.authorization.entity.BasicAuthorizerGroupMapping;
import org.apache.druid.security.basic.authorization.entity.BasicAuthorizerRole;
import org.apache.druid.security.basic.authorization.entity.BasicAuthorizerUser;
import org.apache.druid.segment.column.ColumnType;
import org.apache.druid.server.security.AuthenticationResult;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class is reponsible for maintaining a cache of the authorization database state. The BasicRBACAuthorizer
 * uses an injected BasicAuthorizerCacheManager to make its authorization decisions.
 */
public interface BasicAuthorizerCacheManager
{
  ImmutableSet<String> DEFAULT_ALL_ACCESS_USERS = ImmutableSet.of(
      BasicAuthUtils.ADMIN_NAME,
      BasicAuthUtils.INTERNAL_USER_NAME
  );
  Pattern TENANT_ID_COLUMN_MATCHER = Pattern.compile("^multi.*[-_]([a-z0-9]*)$");
  Pattern ORGANIZATION_ID_MATCHER = Pattern.compile("[a-z0-9]*[-_]([a-z0-9]*)$");

  /**
   * Update this cache manager's local state with fresh information pushed by the coordinator.
   *
   * @param authorizerPrefix         The name of the authorizer this update applies to.
   * @param serializedUserAndRoleMap The updated, serialized user and role maps
   */
  void handleAuthorizerUserUpdate(String authorizerPrefix, byte[] serializedUserAndRoleMap);

  /**
   * Update this cache manager's local state with fresh information pushed by the coordinator.
   *
   * @param authorizerPrefix                 The name of the authorizer this update applies to.
   * @param serializedGroupMappingAndRoleMap The updated, serialized group and role maps
   */
  void handleAuthorizerGroupMappingUpdate(String authorizerPrefix, byte[] serializedGroupMappingAndRoleMap);


  /**
   * Return the cache manager's local view of the user map for the authorizer named `authorizerPrefix`.
   *
   * @param authorizerPrefix The name of the authorizer
   * @return User map
   */
  Map<String, BasicAuthorizerUser> getUserMap(String authorizerPrefix);

  /**
   * Return the cache manager's local view of the role map for the authorizer named `authorizerPrefix`.
   *
   * @param authorizerPrefix The name of the authorizer
   * @return Role map
   */
  Map<String, BasicAuthorizerRole> getRoleMap(String authorizerPrefix);

  /**
   * An empty result means there's no row policy on this table.
   *
  */
  default Optional<Policy> getRowPolicyMap(
      String tableName,
      AuthenticationResult authenticationResult,
      Set<String> roleNames
  )
  {
    Matcher tenantColumnMatcher = TENANT_ID_COLUMN_MATCHER.matcher(tableName);
    if (!tenantColumnMatcher.matches()) {
      return Optional.empty();
    }

    if (DEFAULT_ALL_ACCESS_USERS.contains(authenticationResult.getIdentity())) {
      return Optional.of(NoRestrictionPolicy.INSTANCE);
    }
    String userName = authenticationResult.getIdentity();
    // for user "user1-org1", the org is org1; for user "user2", the org is user2.
    Matcher orgMatcher = ORGANIZATION_ID_MATCHER.matcher(userName);
    String fakeOrganization = orgMatcher.matches() ? orgMatcher.group(1) : userName;
    if (roleNames.contains("org-admin")) {
      return Optional.of(RowFilterPolicy.from(new EqualityFilter(
          tenantColumnMatcher.group(1),
          ColumnType.STRING,
          fakeOrganization,
          null
      )));
    }
    return Optional.of(RowFilterPolicy.from(FalseDimFilter.instance()));
  }

  /**
   * Return the cache manager's local view of the groupMapping map for the authorizer named `authorizerPrefix`.
   *
   * @param authorizerPrefix The name of the authorizer
   * @return GroupMapping map
   */
  Map<String, BasicAuthorizerGroupMapping> getGroupMappingMap(String authorizerPrefix);

  /**
   * Return the cache manager's local view of the groupMapping-role map for the authorizer named `authorizerPrefix`.
   *
   * @param authorizerPrefix The name of the authorizer
   * @return Role map
   */
  Map<String, BasicAuthorizerRole> getGroupMappingRoleMap(String authorizerPrefix);
}
