import os


def load_component_files(args):
    """Load optional component files into a dictionary."""
    components = {}

    component_files = [
        ('problem_description', 'problem_description_file'),
        ('ground_truth', 'ground_truth_file'),
    ]

    for component_name, arg_name in component_files:
        file_path = getattr(args, arg_name, None)
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    components[component_name] = f.read().strip()
                print(f"📄 Loaded {component_name} from {file_path}")
            except Exception as e:
                print(f"⚠️  Warning: Could not load {component_name} from {file_path}: {e}")

    return components


def handle_single_exploit(args, generator):
    """Handle single exploit processing with support for generation, import, and component files."""

    components = load_component_files(args)

    use_dataset_import = hasattr(args, 'import_dataset') and args.import_dataset
    sample_size = args.sample

    if use_dataset_import:
        print(f"🎯 Dataset import mode: {sample_size} problem(s) from {args.import_dataset}")
        print(f"   Filter for ground truth: {'Yes' if args.filter_ground_truth else 'No'}")
        print(f"   Exploit type: {args.exploit}")

        if args.import_dataset in ["primeintellect", "taco-verified"]:
            results = generator.sample_and_import(
                exploit_type=args.exploit,
                n=sample_size,
                filter_with_ground_truth=args.filter_ground_truth,
            )
        else:
            print(f"❌ Unsupported dataset: {args.import_dataset}")
            exit(1)

        successful = 0
        for i, result in enumerate(results, 1):
            if result.get("success", False):
                try:
                    llm_name = generator.generate_directory_name(result["problem_dict"], args.out or "imported_problems")
                    problem_name = f"{llm_name}_{i:03d}" if sample_size > 1 else llm_name
                except Exception as e:
                    print(f"⚠️  Failed to generate LLM name for sample {i}: {e}")
                    safe_exploit_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in args.exploit[:30])
                    problem_name = f"{safe_exploit_name}_{i:03d}" if sample_size > 1 else safe_exploit_name

                if args.out:
                    output_dir = f"{args.out}/{problem_name}" if sample_size > 1 else f"{args.out}/{problem_name}"
                else:
                    output_dir = f"imported_problems/{problem_name}"

                problem_dict = result["problem_dict"]
                generator.save_problem(problem_dict, output_dir, result.get("problem"))
                print(f"💾 Sample {i} saved to {output_dir}")
                if problem_dict.get("exploit_type"):
                    problem_slug = os.path.basename(output_dir)
                    generator.update_exploit_type_list(problem_slug, problem_dict["exploit_type"])
                successful += 1
            else:
                print(f"❌ Sample {i} failed: {result.get('error', 'Unknown error')}")

        if successful > 0:
            print(f"🎉 Successfully imported {successful} out of {len(results)} problems!")
        else:
            print("💥 No problems were successfully imported")
            exit(1)

    elif components.get('problem_description') or components.get('ground_truth'):
        print("🔄 Using component-based generation with provided files...")

        if not components.get('problem_description'):
            print("Error: --problem-description-file required when using component-based generation")
            exit(1)

        result = generator.generate_from_components(
            exploit_type=args.exploit,
            problem_description=components['problem_description'],
            ground_truth_solution=components.get('ground_truth', ''),
        )

        if result["success"]:
            problem_dict = result["problem_dict"]
            generator.save_problem(problem_dict, args.out, result.get("problem"))
            print(f"🎉 Problem generated successfully with provided components!")
            if args.out:
                print(f"   Saved to: {args.out}")
            if problem_dict.get("exploit_type"):
                problem_slug = os.path.basename(args.out)
                generator.update_exploit_type_list(problem_slug, problem_dict["exploit_type"])
        else:
            print(f"💥 Problem generation failed: {result.get('error', 'Unknown error')}")
            exit(1)

    else:
        print("Error: Pure generation is disabled. Use --import for dataset import or provide component files with --problem-description-file/--ground-truth-file.")
        exit(1)


def handle_batch_generate_from_file(args, generator):
    """Handle batch generation from a file containing exploit descriptions.

    Supports both full generation and dataset import modes based on --sample argument.
    """

    components = load_component_files(args)

    try:
        with open(args.exploit_list_file, 'r') as f:
            exploit_descriptions = [line.strip() for line in f if line.strip()]

        if not exploit_descriptions:
            print(f"❌ No exploit descriptions found in {args.exploit_list_file}")
            exit(1)

        use_dataset_import = hasattr(args, 'import_dataset') and args.import_dataset
        sample_size = args.sample

        print(f"📋 Found {len(exploit_descriptions)} exploit descriptions in {args.exploit_list_file}")
        if use_dataset_import:
            print(f"🎯 Dataset import mode: {sample_size} problem(s) per exploit from {args.import_dataset}")
            print(f"   Filter for ground truth: {'Yes' if args.filter_ground_truth else 'No'}")
        else:
            print(f"🎯 Full generation mode: {sample_size} problem(s) per exploit")
        print()

        total_successful = 0
        total_attempted = 0
        batch_results = []

        for i, exploit_description in enumerate(exploit_descriptions, 1):
            print(f"🚀 Processing exploit {i}/{len(exploit_descriptions)}: {exploit_description[:60]}...")

            try:
                if use_dataset_import:
                    if args.import_dataset in ["primeintellect", "taco-verified"]:
                        results = generator.sample_and_import(
                            exploit_description=exploit_description,
                            n=sample_size,
                            filter_with_ground_truth=args.filter_ground_truth,
                        )
                    else:
                        print(f"❌ Unsupported dataset: {args.import_dataset}")
                        exit(1)

                    exploit_successful = 0
                    exploit_attempted = len(results)
                    exploit_results = []

                    for j, result in enumerate(results, 1):
                        if result.get("success", False):
                            try:
                                llm_name = generator.generate_directory_name(result["problem_dict"], args.out or "imported_problems")
                                problem_name = f"{llm_name}_{i:03d}_{j:02d}"
                            except Exception as e:
                                print(f"⚠️  Failed to generate LLM name for exploit {i}, sample {j}: {e}")
                                safe_exploit_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in exploit_description[:30])
                                problem_name = f"{safe_exploit_name}_{i:03d}_{j:02d}"

                            if args.out:
                                output_dir = f"{args.out}/{problem_name}"
                            else:
                                output_dir = f"imported_problems/{problem_name}"

                            generator.save_problem(result["problem_dict"], output_dir, result.get("problem"))
                            print(f"💾 Exploit {i}, sample {j} saved to {output_dir}")
                            exploit_successful += 1
                            exploit_results.append({"success": True, "output_dir": output_dir})
                            if result["problem_dict"].get("exploit_type"):
                                problem_slug = os.path.basename(output_dir)
                                generator.update_exploit_type_list(problem_slug, result["problem_dict"]["exploit_type"]) 
                        else:
                            print(f"❌ Exploit {i}, sample {j} failed: {result.get('error', 'Unknown error')}, traceback: {result.get('traceback', '')}, details: {result.get('validation_result', '')}")
                            exploit_results.append({"success": False, "error": result.get('error', 'Unknown error')})

                else:
                    exploit_successful = 0
                    exploit_attempted = 0
                    exploit_results = []

                    for j in range(sample_size):
                        if args.out:
                            output_dir = f"{args.out}/exploit_{i:03d}_sample_{j+1:02d}"
                        else:
                            safe_exploit_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in exploit_description[:30])
                            output_dir = f"generated_problems/{safe_exploit_name}/sample_{j+1:02d}"

                        try:
                            print(f"🚀 Generating problem {j+1}/{sample_size} for: '{exploit_description[:50]}...'")

                            result = generator.generate_problem(
                                exploit_description=exploit_description,
                            )

                            exploit_attempted += 1
                            if result["success"]:
                                generator.save_problem(
                                    problem_dict=result["problem_dict"],
                                    output_dir=output_dir,
                                    problem=result.get("problem")
                                )
                                print(f"🎉 Problem generation complete! Generated problem '{result['problem_dict']['id']}'")
                                exploit_successful += 1
                                exploit_results.append({"success": True, "output_dir": output_dir})
                                if result["problem_dict"].get("exploit_type"):
                                    problem_slug = os.path.basename(output_dir)
                                    generator.update_exploit_type_list(problem_slug, result["problem_dict"]["exploit_type"]) 
                            else:
                                print(f"💥 Problem generation failed: {result['error']}")
                                exploit_results.append({"success": False, "error": result['error'], "output_dir": output_dir})

                        except Exception as e:
                            exploit_attempted += 1
                            exploit_results.append({"success": False, "error": str(e), "output_dir": output_dir})

                total_successful += exploit_successful
                total_attempted += exploit_attempted

                batch_results.append({
                    "exploit_description": exploit_description,
                    "successful": exploit_successful,
                    "attempted": exploit_attempted,
                    "results": exploit_results
                })

                print(f"   ✅ {exploit_successful}/{exploit_attempted} problems processed successfully")

            except Exception as e:
                print(f"   ❌ Failed to process exploit: {e}")
                batch_results.append({
                    "exploit_description": exploit_description,
                    "successful": 0,
                    "attempted": 0,
                    "error": str(e)
                })

            print()

        print("="*60)
        print("🎭 BATCH PROCESSING SUMMARY")
        print("="*60)
        mode_text = "imported" if use_dataset_import else "generated"
        print(f"📊 Total Results: {total_successful}/{total_attempted} problems {mode_text} successfully")
        print(f"📋 Exploit Breakdown:")

        for i, result in enumerate(batch_results, 1):
            status = "✅" if result["successful"] > 0 else "❌"
            if "error" in result:
                print(f"   {i}. {status} {result['exploit_description'][:50]}... (ERROR: {result['error'][:30]}...)")
            else:
                print(f"   {i}. {status} {result['exploit_description'][:50]}... ({result['successful']}/{result['attempted']})")

        print("="*60)

        if total_successful > 0:
            print(f"🎉 Batch processing completed! {total_successful} problems {mode_text} successfully.")
            if args.out:
                print(f"📁 Problems saved to {args.out}/ subdirectories")
            else:
                base_dir = "imported_problems" if use_dataset_import else "generated_problems"
                print(f"📁 Problems saved to {base_dir}/ subdirectories")
        else:
            print(f"💥 Batch processing failed - no problems were successfully {mode_text}.")
            exit(1)

    except FileNotFoundError:
        print(f"❌ Error: File '{args.exploit_list_file}' not found.")
        exit(1)
    except Exception as e:
        print(f"❌ Error processing exploit descriptions file: {e}")
        exit(1)

    return True


def handle_generate(args):
    """Handle generate for dataset import or component-based assembly."""
    try:
        from djinn.generation import ProblemGenerator

        has_exploit_list = hasattr(args, 'exploit_list_file') and args.exploit_list_file
        has_component_files = any([
            getattr(args, 'problem_description_file', None),
            getattr(args, 'ground_truth_file', None),
        ])

        if not has_exploit_list and not args.exploit:
            print("Error: --exploit is required. Specify the vulnerability to introduce.")
            print("Examples:")
            print("  - Dataset import: --exploit 'timing attack' --import primeintellect --sample 3 --out output_dir")
            print("  - Dataset import: --exploit 'prototype pollution' --import taco-verified --sample 3 --out output_dir")
            print("  - Batch import: --exploit-list-file exploits.txt --import primeintellect --sample 2 --out output_dir")
            exit(1)

        if has_exploit_list and args.exploit:
            print("Error: Cannot specify both --exploit and --exploit-list-file")
            print("Use --exploit for single exploits, --exploit-list-file for batch processing")
            exit(1)

        if has_exploit_list is False and has_component_files and args.exploit and not args.out:
            print("Warning: --out not set; will save to current directory name")

        dataset_name_for_init = args.import_dataset if hasattr(args, 'import_dataset') and args.import_dataset else None
        generator = ProblemGenerator(dataset_name=dataset_name_for_init)

        if has_exploit_list:
            return handle_batch_generate_from_file(args, generator)
        else:
            return handle_single_exploit(args, generator)

    except ImportError as e:
        raise e
    except Exception as e:
        import traceback
        print(f"Error during problem generation: {e}")
        print(f"Exception occurred at:")
        print(traceback.format_exc())
        exit(1)


