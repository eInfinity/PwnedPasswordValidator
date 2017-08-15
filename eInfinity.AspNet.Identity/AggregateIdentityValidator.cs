using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace eInfinity.AspNet.Identity
{
    public class AggregateIdentityValidator<TItem> : IIdentityValidator<TItem>
    {
        IIdentityValidator<TItem>[] _validators;

        public AggregateIdentityValidator(params IIdentityValidator<TItem>[] validators)
        {
            _validators = validators;
        }
        public async Task<IdentityResult> ValidateAsync(TItem item)
        {
            if (item == null)
            {
                throw new ArgumentNullException("item");
            }
            var errors = await GetErrorsAsync(item);
            return errors.Count == 0 ? IdentityResult.Success : IdentityResult.Failed(errors.ToArray());
        }
        protected virtual async Task<IList<string>> GetErrorsAsync(TItem item)
        {
            List<string> errors = new List<string>();
            if (_validators != null && _validators.Length > 0)
            {
                foreach (var validator in _validators)
                {
                    var result = await validator.ValidateAsync(item);
                    if (!result.Succeeded)
                    {
                        errors.AddRange(result.Errors);
                    }
                }
            }
            return errors;
        }
    }
}
