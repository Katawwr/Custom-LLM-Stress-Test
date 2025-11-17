"""
Automatic Improvement Application System
Applies generated improvements to the AI system and creates versioned backups
"""

import json
import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Dict
import re


class AutomaticImprovementApplicator:
    """
    Applies improvements to design_ai_core.py with versioning and rollback support
    """
    
    def __init__(self, 
                 core_file: str = "design_ai_core.py",
                 improvements_dir: str = "improvements",
                 versions_dir: str = "versions"):
        
        self.core_file = Path(core_file)
        self.improvements_dir = Path(improvements_dir)
        self.versions_dir = Path(versions_dir)
        self.versions_dir.mkdir(exist_ok=True)
        
        if not self.core_file.exists():
            raise FileNotFoundError(f"Core file not found: {self.core_file}")
    
    def load_latest_plan(self) -> Dict:
        """Load the most recent improvement plan"""
        
        plan_files = sorted(self.improvements_dir.glob("plan_*.json"))
        
        if not plan_files:
            raise FileNotFoundError("No improvement plans found")
        
        latest = plan_files[-1]
        print(f"📋 Loading plan: {latest.name}")
        
        with open(latest) as f:
            return json.load(f)
    
    def load_improvement(self, improvement_id: str) -> Dict:
        """Load a specific improvement"""
        
        imp_file = self.improvements_dir / f"{improvement_id}.json"
        
        if not imp_file.exists():
            raise FileNotFoundError(f"Improvement not found: {improvement_id}")
        
        with open(imp_file) as f:
            return json.load(f)
    
    def create_backup(self) -> Path:
        """Create timestamped backup of current version"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = self.versions_dir / f"design_ai_core_v{timestamp}.py"
        
        shutil.copy2(self.core_file, backup_file)
        
        print(f"💾 Backup created: {backup_file.name}")
        return backup_file
    
    def apply_improvements(self, plan: Dict, preview: bool = False) -> bool:
        """
        Apply all improvements from plan
        
        Args:
            plan: Improvement plan dictionary
            preview: If True, only show what would be changed
        
        Returns:
            True if successful
        """
        
        print(f"\n{'='*70}")
        print("🔧 APPLYING IMPROVEMENTS")
        print(f"{'='*70}\n")
        
        if not preview:
            # Create backup before making changes
            self.create_backup()
        
        # Load current file
        with open(self.core_file) as f:
            current_content = f.read()
        
        modified_content = current_content
        applied_count = 0
        
        # Apply each improvement
        for imp_data in plan['improvements']:
            improvement = self.load_improvement(imp_data['id'])
            
            print(f"Applying: {improvement['description']}")
            
            if improvement['target'] == 'system_prompt':
                modified_content = self._apply_system_prompt_change(
                    modified_content, improvement, preview
                )
            
            elif improvement['target'] == 'input_validator':
                modified_content = self._apply_input_validator_change(
                    modified_content, improvement, preview
                )
            
            elif improvement['target'] == 'output_filter':
                modified_content = self._apply_output_filter_change(
                    modified_content, improvement, preview
                )
            
            elif improvement['target'] == 'business_rules':
                modified_content = self._apply_business_rules_change(
                    modified_content, improvement, preview
                )
            
            applied_count += 1
            print(f"  ✓ Applied ({applied_count}/{len(plan['improvements'])})")
        
        if preview:
            print("\n📝 PREVIEW MODE - No changes written")
            print("   Run without --preview to apply changes")
            return True
        
        # Write modified content
        with open(self.core_file, 'w') as f:
            f.write(modified_content)
        
        print(f"\n✅ Successfully applied {applied_count} improvements")
        print(f"💾 Updated: {self.core_file}")
        
        # Create version metadata
        self._save_version_metadata(plan, applied_count)
        
        return True
    
    def _apply_system_prompt_change(self, content: str, improvement: Dict, preview: bool) -> str:
        """Apply system prompt improvements"""
        
        addition = improvement['code_or_text']
        
        # Find build_system_prompt function
        pattern = r'(def build_system_prompt\(\) -> str:.*?return\s+f?""")(.*?)(""")'
        
        match = re.search(pattern, content, re.DOTALL)
        
        if not match:
            print(f"  ⚠️  Warning: Could not find system prompt builder")
            return content
        
        before, current_prompt, after = match.groups()
        
        if improvement['change_type'] == 'add':
            # Add to end of prompt
            new_prompt = current_prompt + addition
        
        elif improvement['change_type'] == 'modify':
            # Replace section (more complex, would need markers)
            new_prompt = current_prompt + "\n\n" + addition
        
        else:
            new_prompt = current_prompt
        
        new_content = content[:match.start()] + before + new_prompt + after + content[match.end():]
        
        if preview:
            print(f"  📝 Would add {len(addition)} characters to system prompt")
        
        return new_content
    
    def _apply_input_validator_change(self, content: str, improvement: Dict, preview: bool) -> str:
        """Apply input validator improvements"""
        
        new_code = improvement['code_or_text']
        
        if improvement['change_type'] == 'add':
            # Add new validator class before main SecureDesignAI class
            insertion_point = content.find('class SecureDesignAI:')
            
            if insertion_point == -1:
                print(f"  ⚠️  Warning: Could not find insertion point")
                return content
            
            # Insert before main class
            new_content = (
                content[:insertion_point] +
                new_code + "\n\n\n" +
                content[insertion_point:]
            )
        
        elif improvement['change_type'] == 'modify':
            # Replace existing InputValidator class
            pattern = r'class InputValidator:.*?(?=class\s|\Z)'
            new_content = re.sub(pattern, new_code + "\n\n", content, flags=re.DOTALL)
        
        else:
            new_content = content
        
        if preview:
            print(f"  📝 Would add/modify InputValidator ({len(new_code)} chars)")
        
        return new_content
    
    def _apply_output_filter_change(self, content: str, improvement: Dict, preview: bool) -> str:
        """Apply output filter improvements"""
        
        new_code = improvement['code_or_text']
        
        if improvement['change_type'] == 'add':
            # Add new filter class
            insertion_point = content.find('class OutputFilter:')
            
            if insertion_point == -1:
                print(f"  ⚠️  Warning: Could not find insertion point")
                return content
            
            # Find end of OutputFilter class
            end_pattern = r'class OutputFilter:.*?(?=\nclass\s|\n(?:def\s|class\s|$))'
            match = re.search(end_pattern, content, re.DOTALL)
            
            if match:
                insertion_point = match.end()
                new_content = (
                    content[:insertion_point] +
                    "\n\n" + new_code +
                    content[insertion_point:]
                )
            else:
                new_content = content
        
        else:
            new_content = content
        
        if preview:
            print(f"  📝 Would add/modify OutputFilter ({len(new_code)} chars)")
        
        return new_content
    
    def _apply_business_rules_change(self, content: str, improvement: Dict, preview: bool) -> str:
        """Apply business rules improvements"""
        
        new_code = improvement['code_or_text']
        
        # Add new validator classes before BusinessRuleValidator
        insertion_point = content.find('class BusinessRuleValidator:')
        
        if insertion_point == -1:
            # Add before SecureDesignAI class
            insertion_point = content.find('class SecureDesignAI:')
        
        if insertion_point == -1:
            print(f"  ⚠️  Warning: Could not find insertion point")
            return content
        
        new_content = (
            content[:insertion_point] +
            new_code + "\n\n\n" +
            content[insertion_point:]
        )
        
        # Also need to instantiate in SecureDesignAI.__init__
        if 'EnhancedPricingValidator' in new_code:
            self._add_validator_instantiation(new_content, 'pricing_validator', 'EnhancedPricingValidator')
        
        if 'EnhancedPaymentValidator' in new_code:
            self._add_validator_instantiation(new_content, 'payment_validator', 'EnhancedPaymentValidator')
        
        if preview:
            print(f"  📝 Would add business rule validator ({len(new_code)} chars)")
        
        return new_content
    
    def _add_validator_instantiation(self, content: str, var_name: str, class_name: str) -> str:
        """Add validator instantiation to __init__"""
        
        # Find SecureDesignAI.__init__
        pattern = r'(class SecureDesignAI:.*?def __init__.*?)(self\.business_validator = BusinessRuleValidator\(\))'
        
        match = re.search(pattern, content, re.DOTALL)
        
        if match:
            before, existing_line = match.groups()
            new_line = f"\n        self.{var_name} = {class_name}()"
            
            return (
                content[:match.start(2)] +
                existing_line + new_line +
                content[match.end(2):]
            )
        
        return content
    
    def _save_version_metadata(self, plan: Dict, applied_count: int):
        """Save metadata about this version"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        metadata_file = self.versions_dir / f"metadata_v{timestamp}.json"
        
        metadata = {
            'timestamp': timestamp,
            'applied_improvements': applied_count,
            'improvements': plan['improvements'],
            'previous_version': self._get_previous_version(),
            'rollback_available': True
        }
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def _get_previous_version(self) -> str:
        """Get previous version filename"""
        
        versions = sorted(self.versions_dir.glob("design_ai_core_v*.py"))
        
        if len(versions) >= 2:
            return versions[-2].name
        elif len(versions) == 1:
            return versions[-1].name
        else:
            return "none"
    
    def rollback(self, version: str = None):
        """Rollback to a previous version"""
        
        if version is None:
            # Rollback to most recent backup
            versions = sorted(self.versions_dir.glob("design_ai_core_v*.py"))
            
            if not versions:
                print("❌ No backup versions available")
                return False
            
            version_file = versions[-1]
        else:
            version_file = self.versions_dir / version
            
            if not version_file.exists():
                print(f"❌ Version not found: {version}")
                return False
        
        print(f"🔄 Rolling back to: {version_file.name}")
        
        # Create backup of current (even if rolling back)
        self.create_backup()
        
        # Restore old version
        shutil.copy2(version_file, self.core_file)
        
        print(f"✅ Rollback complete")
        return True
    
    def list_versions(self):
        """List all available versions"""
        
        versions = sorted(self.versions_dir.glob("design_ai_core_v*.py"))
        metadata_files = sorted(self.versions_dir.glob("metadata_v*.json"))
        
        print(f"\n{'='*70}")
        print("📚 AVAILABLE VERSIONS")
        print(f"{'='*70}\n")
        
        for version in versions:
            timestamp = version.stem.split('_v')[1]
            
            # Find matching metadata
            metadata_file = self.versions_dir / f"metadata_v{timestamp}.json"
            
            if metadata_file.exists():
                with open(metadata_file) as f:
                    metadata = json.load(f)
                
                print(f"Version: {version.name}")
                print(f"  Time: {timestamp}")
                print(f"  Improvements: {metadata.get('applied_improvements', 'unknown')}")
                print(f"  Rollback available: ✅")
                print()
            else:
                print(f"Version: {version.name}")
                print(f"  Time: {timestamp}")
                print(f"  Metadata: Not available")
                print()


def main():
    """Run improvement application"""
    
    import sys
    
    applicator = AutomaticImprovementApplicator()
    
    # Check for command line args
    if '--list' in sys.argv:
        applicator.list_versions()
        return
    
    if '--rollback' in sys.argv:
        version = sys.argv[sys.argv.index('--rollback') + 1] if len(sys.argv) > sys.argv.index('--rollback') + 1 else None
        applicator.rollback(version)
        return
    
    preview = '--preview' in sys.argv
    
    try:
        # Load latest plan
        plan = applicator.load_latest_plan()
        
        print(f"\n{'='*70}")
        print("📋 IMPROVEMENT PLAN SUMMARY")
        print(f"{'='*70}\n")
        
        print(f"Total improvements: {plan['total_improvements']}")
        print(f"System prompt changes: {len(plan['improvements_by_target']['system_prompt'])}")
        print(f"Input validator changes: {len(plan['improvements_by_target']['input_validator'])}")
        print(f"Output filter changes: {len(plan['improvements_by_target']['output_filter'])}")
        print(f"Business rules changes: {len(plan['improvements_by_target']['business_rules'])}")
        
        # Apply improvements
        success = applicator.apply_improvements(plan, preview=preview)
        
        if success and not preview:
            print(f"\n✅ All improvements applied successfully")
            print(f"📝 Next step: Run verification tests with:")
            print(f"   python auto_verify_improvements.py")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
