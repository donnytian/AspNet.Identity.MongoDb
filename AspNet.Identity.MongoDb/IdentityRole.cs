using System;
using System.Collections.Generic;
using System.Text;

namespace AspNet.Identity.MongoDb
{
    /// <summary>Represents a role in the identity system</summary>
    /// <typeparam name="TKey">The type used for the primary key for the role.</typeparam>
    public class IdentityRole<TKey> where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Initializes a new instance of <see cref="T:Microsoft.AspNetCore.Identity.IdentityRole`1" />.
        /// </summary>
        public IdentityRole()
        {
            Claims = new List<IdentityClaim>();
        }

        /// <inheritdoc />
        /// <summary>
        /// Initializes a new instance of <see cref="T:Microsoft.AspNetCore.Identity.IdentityRole`1" />.
        /// </summary>
        /// <param name="roleName">The role name.</param>
        public IdentityRole(string roleName) : this()
        {
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
        public virtual List<IdentityClaim> Claims { get; }

        /// <summary>Returns the name of the role.</summary>
        /// <returns>The name of the role.</returns>
        public override string ToString()
        {
            return Name;
        }
    }
}
