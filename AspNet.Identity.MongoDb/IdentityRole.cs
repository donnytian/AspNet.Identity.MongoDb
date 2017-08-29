using System;
using System.Collections.Generic;

namespace AspNet.Identity.MongoDb
{
    /// <summary>Represents a role in the identity system</summary>
    /// <typeparam name="TKey">The type used for the primary key for the role.</typeparam>
    /// <typeparam name="TIdentityClaim">The type of the class representing a role claim.</typeparam>
    public class IdentityRole<TKey, TIdentityClaim>
        where TKey : IEquatable<TKey>
        where TIdentityClaim : IdentityClaim
    {
        /// <summary>
        /// Initializes a new instance of <see cref="T:Microsoft.AspNetCore.Identity.IdentityRole`1" />.
        /// </summary>
        public IdentityRole()
        {
            Claims = new List<TIdentityClaim>();
        }

        /// <inheritdoc />
        /// <summary>
        /// Initializes a new instance of <see cref="T:Microsoft.AspNetCore.Identity.IdentityRole`1" />.
        /// </summary>
        /// <param name="roleName">The role name.</param>
        public IdentityRole(string roleName) : this()
        {
            // ReSharper disable once VirtualMemberCallInConstructor
            Name = roleName;
        }

        /// <summary>Gets or sets the primary key for this role.</summary>
        public virtual TKey Id { get; set; }

        /// <summary>Gets or sets the name for this role.</summary>
        public virtual string Name { get; set; }

        /// <summary>Gets or sets the normalized name for this role.</summary>
        public virtual string NormalizedName { get; set; }

        /// <summary>
        /// Gets the claims for the current role.
        /// </summary>
        public virtual List<TIdentityClaim> Claims { get; }

        /// <summary>Returns the name of the role.</summary>
        /// <returns>The name of the role.</returns>
        public override string ToString()
        {
            return Name;
        }
    }
}
