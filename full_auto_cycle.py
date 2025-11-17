"""
Complete Automated Improvement Cycle
Orchestrates: Test → Analyze → Improve → Apply → Verify → Repeat
"""

import asyncio
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List


class AutomatedImprovementCycle:
    """
    Full automated cycle that continuously improves the AI system
    
    Workflow:
    1. Run security tests
    2. Analyze vulnerabilities
    3. Generate improvements
    4. Apply improvements (with user approval)
    5. Verify fixes
    6. Repeat if needed
    """
    
    def __init__(self, 
                 max_iterations: int = 5,
                 auto_apply: bool = False,
                 min_fix_rate: float = 0.90):
        
        self.max_iterations = max_iterations
        self.auto_apply = auto_apply
        self.min_fix_rate = min_fix_rate
        
        self.cycle_history = []
        self.history_file = Path("cycle_history.json")
        
        # Load history
        if self.history_file.exists():
            with open(self.history_file) as f:
                self.cycle_history = json.load(f)
    
    def save_history(self):
        """Save cycle history"""
        with open(self.history_file, 'w') as f:
            json.dump(self.cycle_history, f, indent=2)
    
    async def run_security_tests(self) -> Dict:
        """Run comprehensive security test suite"""
        
        print(f"\n{'='*70}")
        print("🔒 STEP 1: RUNNING SECURITY TESTS")
        print(f"{'='*70}\n")
        
        from continuous_orchestrator import ContinuousSecurityOrchestrator
        from design_ai_core import SecureDesignAI
        
        ai_system = SecureDesignAI(api_key="your-key-here")
        
        # Run focused test suite (faster than full continuous testing)
        print("Running adversarial attack generation...")
        from adversarial_attack_generator import AdversarialAttackGenerator
        
        adv_gen = AdversarialAttackGenerator(
            ai_system=ai_system,
            api_key="your-key-here",
            population_size=20,
            mutation_rate=0.3
        )
        
        hall_of_fame = await adv_gen.evolve(generations=5)
        adv_gen.export_results(f"continuous_testing_results/adversarial_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        print("\nRunning fuzzing tests...")
        from fuzzing_engine import FuzzingEngine
        
        fuzzer = FuzzingEngine(ai_system)
        base_inputs = [a.payload for a in hall_of_fame[:5]]
        fuzzer.fuzz(base_inputs=base_inputs, iterations=50)
        fuzzer.export_results(f"continuous_testing_results/fuzzing_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        print("\nRunning regression suite...")
        from redteam_kit import RedTeamExecutor, SecurityAnalyzer
        
        executor = RedTeamExecutor(ai_system)
        results = executor.run_full_suite()
        
        analyzer = SecurityAnalyzer(
            results=executor.results,
            multi_turn_results=results.get('multi_turn_attacks', [])
        )
        
        analyzer.generate_report(f"continuous_testing_results/full_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        analysis = analyzer.analyze()
        
        return {
            'vulnerabilities_found': analysis['summary']['vulnerabilities_found'],
            'total_tests': analysis['summary']['total_tests'],
            'by_severity': analysis['by_severity']
        }
    
    async def analyze_and_improve(self) -> Dict:
        """Analyze test results and generate improvements"""
        
        print(f"\n{'='*70}")
        print("🔧 STEP 2: ANALYZING & GENERATING IMPROVEMENTS")
        print(f"{'='*70}\n")
        
        from auto_improvement_engine import AutomaticImprovementEngine
        
        engine = AutomaticImprovementEngine()
        vulnerabilities, improvements, plan = engine.run()
        
        return {
            'vulnerabilities': len(vulnerabilities),
            'improvements': len(improvements),
            'plan': plan
        }
    
    async def apply_improvements(self, plan: Dict, preview: bool = False) -> bool:
        """Apply generated improvements"""
        
        print(f"\n{'='*70}")
        print("📝 STEP 3: APPLYING IMPROVEMENTS")
        print(f"{'='*70}\n")
        
        from auto_apply_improvements import AutomaticImprovementApplicator
        
        applicator = AutomaticImprovementApplicator()
        
        # Show preview
        applicator.apply_improvements(plan, preview=True)
        
        if not self.auto_apply and not preview:
            # Ask for confirmation
            print(f"\n{'='*70}")
            print("⚠️  APPLY CHANGES?")
            print(f"{'='*70}\n")
            print("These improvements will modify design_ai_core.py")
            print("A backup will be created automatically")
            print("\nOptions:")
            print("  y - Apply all improvements")
            print("  n - Skip this iteration")
            print("  v - View detailed changes")
            print("  q - Quit cycle")
            
            choice = input("\nYour choice (y/n/v/q): ").lower().strip()
            
            if choice == 'q':
                print("Cycle aborted by user")
                return False
            elif choice == 'n':
                print("Skipping improvements this iteration")
                return False
            elif choice == 'v':
                # Show detailed improvements
                for imp in plan['improvements']:
                    print(f"\n{imp['description']}")
                    print(f"  Target: {imp['target']}")
                    print(f"  Expected impact: {imp['expected_impact']}")
                
                # Ask again
                choice = input("\nApply? (y/n): ").lower().strip()
                if choice != 'y':
                    return False
        
        # Apply improvements
        success = applicator.apply_improvements(plan, preview=False)
        
        return success
    
    async def verify_improvements(self) -> Dict:
        """Verify that improvements fixed vulnerabilities"""
        
        print(f"\n{'='*70}")
        print("🔬 STEP 4: VERIFYING IMPROVEMENTS")
        print(f"{'='*70}\n")
        
        from auto_verify_improvements import AutomaticVerificationSystem
        
        verifier = AutomaticVerificationSystem()
        report = await verifier.run()
        
        return report
    
    def check_success(self, verification_report: Dict) -> bool:
        """Check if improvements were successful"""
        
        fix_rate_str = verification_report['summary']['fix_rate'].rstrip('%')
        fix_rate = float(fix_rate_str) / 100
        
        return fix_rate >= self.min_fix_rate
    
    async def run_cycle(self) -> Dict:
        """Run one complete improvement cycle"""
        
        cycle_id = f"cycle_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        print(f"\n{'='*70}")
        print(f"🔄 STARTING IMPROVEMENT CYCLE: {cycle_id}")
        print(f"{'='*70}\n")
        
        cycle_result = {
            'cycle_id': cycle_id,
            'timestamp': datetime.now().isoformat(),
            'steps': {}
        }
        
        try:
            # Step 1: Run tests
            test_results = await self.run_security_tests()
            cycle_result['steps']['testing'] = test_results
            
            if test_results['vulnerabilities_found'] == 0:
                print(f"\n✅ No vulnerabilities found! System is secure.")
                cycle_result['success'] = True
                cycle_result['reason'] = 'no_vulnerabilities'
                return cycle_result
            
            # Step 2: Generate improvements
            improvement_results = await self.analyze_and_improve()
            cycle_result['steps']['improvements'] = improvement_results
            
            # Step 3: Apply improvements
            applied = await self.apply_improvements(improvement_results['plan'])
            cycle_result['steps']['applied'] = applied
            
            if not applied:
                cycle_result['success'] = False
                cycle_result['reason'] = 'improvements_not_applied'
                return cycle_result
            
            # Step 4: Verify
            verification = await self.verify_improvements()
            cycle_result['steps']['verification'] = verification['summary']
            
            # Check success
            success = self.check_success(verification)
            cycle_result['success'] = success
            cycle_result['reason'] = 'verified' if success else 'verification_failed'
            
            return cycle_result
        
        except Exception as e:
            print(f"\n❌ Cycle failed: {e}")
            import traceback
            traceback.print_exc()
            
            cycle_result['success'] = False
            cycle_result['reason'] = f'error: {str(e)}'
            return cycle_result
    
    async def run_continuous(self):
        """Run continuous improvement cycles"""
        
        print(f"\n{'='*70}")
        print("🔄 CONTINUOUS IMPROVEMENT MODE")
        print(f"{'='*70}\n")
        print(f"Max iterations: {self.max_iterations}")
        print(f"Min fix rate: {self.min_fix_rate * 100:.0f}%")
        print(f"Auto-apply: {self.auto_apply}")
        print()
        
        iteration = 0
        
        while iteration < self.max_iterations:
            iteration += 1
            
            print(f"\n{'='*70}")
            print(f"ITERATION {iteration}/{self.max_iterations}")
            print(f"{'='*70}\n")
            
            # Run cycle
            cycle_result = await self.run_cycle()
            
            # Save to history
            self.cycle_history.append(cycle_result)
            self.save_history()
            
            # Print results
            self.print_cycle_summary(cycle_result)
            
            # Check if we should continue
            if cycle_result['success']:
                if cycle_result['reason'] == 'no_vulnerabilities':
                    print(f"\n✅ System is fully secure. Stopping.")
                    break
                elif cycle_result['reason'] == 'verified':
                    print(f"\n✅ Improvements successful!")
                    
                    # Check if there are remaining vulnerabilities
                    remaining = cycle_result['steps']['verification'].get('still_vulnerable', 0)
                    
                    if remaining > 0:
                        print(f"\n💡 {remaining} vulnerabilities remain. Running another cycle...")
                        continue
                    else:
                        print(f"\n✅ All vulnerabilities fixed! Stopping.")
                        break
            
            else:
                print(f"\n⚠️  Cycle did not achieve target fix rate.")
                
                if not self.auto_apply:
                    choice = input("\nContinue with another cycle? (y/n): ").lower().strip()
                    if choice != 'y':
                        print("Stopping improvement cycles")
                        break
        
        # Final summary
        self.print_final_summary()
    
    def print_cycle_summary(self, cycle_result: Dict):
        """Print summary of single cycle"""
        
        print(f"\n{'='*70}")
        print("📊 CYCLE SUMMARY")
        print(f"{'='*70}\n")
        
        print(f"Cycle ID: {cycle_result['cycle_id']}")
        print(f"Success: {'✅' if cycle_result['success'] else '❌'}")
        print(f"Reason: {cycle_result['reason']}")
        
        if 'testing' in cycle_result['steps']:
            test = cycle_result['steps']['testing']
            print(f"\nTesting:")
            print(f"  Vulnerabilities: {test['vulnerabilities_found']}")
            print(f"  Total tests: {test['total_tests']}")
        
        if 'improvements' in cycle_result['steps']:
            imp = cycle_result['steps']['improvements']
            print(f"\nImprovements:")
            print(f"  Generated: {imp['improvements']}")
            print(f"  Vulnerabilities addressed: {imp['vulnerabilities']}")
        
        if 'verification' in cycle_result['steps']:
            ver = cycle_result['steps']['verification']
            print(f"\nVerification:")
            print(f"  Fix rate: {ver['fix_rate']}")
            print(f"  Still vulnerable: {ver['still_vulnerable']}")
    
    def print_final_summary(self):
        """Print summary of all cycles"""
        
        print(f"\n{'='*70}")
        print("📊 FINAL SUMMARY - ALL CYCLES")
        print(f"{'='*70}\n")
        
        total_cycles = len(self.cycle_history)
        successful = sum(1 for c in self.cycle_history if c['success'])
        
        print(f"Total cycles: {total_cycles}")
        print(f"Successful: {successful}")
        print(f"Failed: {total_cycles - successful}")
        
        if self.cycle_history:
            # Show progression
            print(f"\nProgression:")
            
            for i, cycle in enumerate(self.cycle_history, 1):
                status = '✅' if cycle['success'] else '❌'
                
                vulns_before = cycle['steps'].get('testing', {}).get('vulnerabilities_found', '?')
                vulns_after = cycle['steps'].get('verification', {}).get('still_vulnerable', '?')
                
                print(f"  {i}. {status} {vulns_before} vulns → {vulns_after} remaining")
        
        print(f"\n📝 Full history saved in: cycle_history.json")


async def main():
    """Run automated improvement cycle"""
    
    import sys
    
    # Parse arguments
    auto_apply = '--auto' in sys.argv
    max_iterations = 5
    
    if '--max-iterations' in sys.argv:
        idx = sys.argv.index('--max-iterations')
        if len(sys.argv) > idx + 1:
            max_iterations = int(sys.argv[idx + 1])
    
    # Create cycle manager
    cycle = AutomatedImprovementCycle(
        max_iterations=max_iterations,
        auto_apply=auto_apply,
        min_fix_rate=0.90
    )
    
    # Run continuous improvement
    await cycle.run_continuous()
    
    print(f"\n✅ Improvement cycle complete!")


if __name__ == "__main__":
    asyncio.run(main())
